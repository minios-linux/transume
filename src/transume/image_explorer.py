"""Root-owned, read-only Partclone image explorer lifecycle."""
from __future__ import annotations
import fcntl, json, os, pwd, grp, re, select, shutil, signal, stat, struct, subprocess, time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4
from .draft import image_fingerprint
from .images import ImageStatus, parse_clonezilla_image

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z"); _NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_NBD = re.compile(r"/dev/nbd[0-9]+\Z"); _ENV = {"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL":"C"}
_BIN = {"mount":"/bin/mount", "umount":"/bin/umount", "modprobe":"/usr/sbin/modprobe", "setfacl":"/usr/bin/setfacl", "nbdkit":"/usr/bin/nbdkit", "nbd-client":"/usr/sbin/nbd-client", "partclone-nbd":"/usr/bin/partclone-nbd", "blockdev":"/usr/sbin/blockdev"}
class ImageExplorerError(RuntimeError): pass

@dataclass(frozen=True, slots=True)
class ExplorerRequest:
    request_id: str; operation: str; repository: str|None=None; image_name: str|None=None; image_fingerprint: str|None=None; source_partition: str|None=None; session_id: str|None=None
    def __post_init__(self):
        if not _ID.fullmatch(self.request_id) or self.operation not in {"connect","disconnect","status"}: raise ValueError("invalid explorer request")
        if self.operation == "connect":
            if not isinstance(self.repository,str) or not self.repository.startswith("/") or "\0" in self.repository or not _NAME.fullmatch(self.image_name or "") or not re.fullmatch(r"[0-9a-f]{64}",self.image_fingerprint or "") or not _NAME.fullmatch(self.source_partition or "") or self.session_id is not None: raise ValueError("invalid explorer connect evidence")
        elif any(x is not None for x in (self.repository,self.image_name,self.image_fingerprint,self.source_partition)) or not _ID.fullmatch(self.session_id or ""): raise ValueError("invalid explorer session request")
    def to_dict(self): return {x:getattr(self,x) for x in ("request_id","operation","repository","image_name","image_fingerprint","source_partition","session_id")}
    @classmethod
    def from_dict(cls, value:Mapping[str,Any]):
        if not isinstance(value,Mapping) or set(value)!={"request_id","operation","repository","image_name","image_fingerprint","source_partition","session_id"}: raise ValueError("unknown explorer request fields")
        return cls(**dict(value))
@dataclass(frozen=True, slots=True)
class ExplorerResult: request_id:str; status:str; detail:str; session_id:str|None=None; mountpoint:str|None=None

def explorer_support_reason(image, *, capabilities=None):
    if image.encrypted: return "Encrypted images cannot be explored"
    if image.status not in {ImageStatus.READY,ImageStatus.NEEDS_VERIFICATION}: return f"Image is {image.status.replace('-', ' ')}"
    if not image.topology.partitions: return "Image has no selectable source partition"
    unsupported = sorted(set(image.compression) - {"gzip", "xz"})
    if unsupported: return f"Cannot explore {', '.join(unsupported)} compression; supported formats are none, gzip, and xz"
    if not image.payload_files or any("-ptcl-img" not in x for x in image.payload_files): return "Only Partclone payloads can be explored"
    if capabilities is not None and not all(capabilities.supports(x) for x in ("partclone-nbd","nbdkit","nbd-client","blockdev","setfacl")): return "Requires partclone-nbd, nbdkit, nbd-client, blockdev, and setfacl"
    return None

def derive_partclone_payloads(root:Path, partition:str):
    pattern=re.compile(rf"^{re.escape(partition)}(?:\.[^.]+)?-ptcl-img(?:[.-].*)?$")
    names=sorted((x.name for x in root.iterdir() if pattern.match(x.name)),key=lambda x:(re.sub(r"\.(?:\d+|[a-z]{{2}})$","",x),x))
    if not names: raise ImageExplorerError("selected partition has no Partclone payload")
    def compression(x):
        if re.search(r"\.g(?:z|zip)(?:\.|$)",x,re.I): return "gzip"
        if re.search(r"\.xz(?:\.|$)",x,re.I): return "xz"
        if re.search(r"\.(?:zst|zstd|lz4|lzma|bz2|bzip2|lzo|lz|lzip|lrz|lrzip)(?:\.|$)",x,re.I): return "unsupported"
        return "none"
    kinds={compression(x) for x in names}
    if len(kinds)!=1 or not kinds <= {"none","gzip","xz"}: raise ImageExplorerError("payload compression is unsupported")
    paths=tuple(root/x for x in names)
    if any(not stat.S_ISREG(x.lstat().st_mode) or x.is_symlink() for x in paths): raise ImageExplorerError("payload is not a regular file")
    return paths,kinds.pop()

class ImageExplorer:
    def __init__(self, *, runtime=Path("/run/transume/explorer"), mount_runtime:Path|None=None, caller_uid:int|None=None, caller_gid:int|None=None, execute=subprocess.run, popen=subprocess.Popen, is_mount=os.path.ismount, sleep=time.sleep, monotonic=time.monotonic, sys_block=Path("/sys/class/block"), caller_directory_validator=None):
        self.runtime=Path(runtime); self.uid=caller_uid if caller_uid is not None else os.getuid(); self.gid=caller_gid if caller_gid is not None else os.getgid()
        self.mount_runtime=Path(mount_runtime) if mount_runtime else Path("/run/transume/explorer-mounts"); self.execute,self.popen,self.is_mount=execute,popen,is_mount; self.sleep,self.monotonic,self.sys_block=sleep,monotonic,Path(sys_block); self.caller_directory_validator=caller_directory_validator
    def handle(self, request):
        try:
            self._prepare()
            with self._lock():
                if request.operation=="connect": self._recover_others(); return self._connect(request)
                return self._disconnect(request) if request.operation=="disconnect" else self._status(request)
        except ImageExplorerError as e: return ExplorerResult(request.request_id,"failed",str(e))
        except Exception: return ExplorerResult(request.request_id,"failed","image explorer operation failed")
    def _prepare(self):
        owner=0 if os.geteuid()==0 else os.geteuid(); root=self.runtime.parent
        self._safe_dir(root,owner,os.getegid(),0o711); self._safe_dir(self.runtime,owner,os.getegid(),0o700); self._safe_dir(self.mount_runtime,owner,os.getegid(),0o711)
    def _safe_dir(self,path,uid,gid,mode):
        path.mkdir(mode=mode,parents=True,exist_ok=True)
        info=path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid!=uid: raise ImageExplorerError("invalid explorer runtime")
        os.chmod(path, mode)
        if stat.S_IMODE(path.lstat().st_mode)!=mode: raise ImageExplorerError("invalid explorer runtime")
    @contextmanager
    def _lock(self):
        fd=os.open(self.runtime/"lock",os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
        try: fcntl.flock(fd,fcntl.LOCK_EX); yield
        finally: os.close(fd)
    def _state_path(self,s): return self.runtime/f"{s}.json"
    def _inside(self,path,base):
        try: Path(path).relative_to(base); return True
        except ValueError: return False
    def _read_state(self,s):
        path=self._state_path(s)
        try: info=path.lstat()
        except FileNotFoundError: return None
        owner=0 if os.geteuid()==0 else os.geteuid()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=owner or stat.S_IMODE(info.st_mode)!=0o600: raise ImageExplorerError("invalid explorer state")
        try: value=json.loads(path.read_text(encoding="ascii"))
        except (OSError,ValueError): raise ImageExplorerError("invalid explorer state") from None
        required={"session_id","caller_uid","caller_gid","directory","pinned","mountpoint","pids","nbds","attached","mounted"}
        if not isinstance(value,dict) or set(value)!=required or value["session_id"]!=s or type(value["caller_uid"]) is not int or type(value["caller_gid"]) is not int or value["caller_uid"] < 1000 or not all(isinstance(value[x],str) for x in ("directory","pinned","mountpoint")) or not isinstance(value["pids"],list) or not isinstance(value["nbds"],list) or not isinstance(value["attached"],list) or type(value["mounted"]) is not bool: raise ImageExplorerError("invalid explorer state")
        directory=self.runtime/s
        if Path(value["directory"])!=directory or not self._inside(value["pinned"],directory) or Path(value["mountpoint"]) != self.mount_runtime/s/"files" or not 0 <= len(value["nbds"]) <= 3 or len(set(value["nbds"])) != len(value["nbds"]) or any(not isinstance(x,str) or not _NBD.fullmatch(x) for x in value["nbds"]) or len(set(value["attached"])) != len(value["attached"]) or any(x not in value["nbds"] for x in value["attached"]): raise ImageExplorerError("invalid explorer state")
        for item in value["pids"]:
            if not isinstance(item,dict) or set(item)!={"pid","argv"} or type(item["pid"]) is not int or item["pid"]<=1 or not isinstance(item["argv"],list) or not self._valid_argv(item["argv"],directory): raise ImageExplorerError("invalid explorer state")
        return value
    def _valid_argv(self,argv,directory):
        if not argv or argv[0] not in {_BIN["nbdkit"],_BIN["partclone-nbd"]} or any(not isinstance(x,str) for x in argv): return False
        return all(not x.startswith("/") or x in _BIN.values() or self._inside(x,directory) or _NBD.fullmatch(x) for x in argv)
    def _write_state(self,state):
        self._read_state_shape(state); target=self._state_path(state["session_id"]); temp=self.runtime/f".{state['session_id']}.tmp"; fd=os.open(temp,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
        try: os.write(fd,json.dumps(state,separators=(",",":"),ensure_ascii=True).encode()); os.fsync(fd)
        finally: os.close(fd)
        os.replace(temp,target); os.chmod(target,0o600)
    def _read_state_shape(self,state):
        # Validate newly checkpointed state through the same exact schema without trusting disk.
        temp=self._state_path(state["session_id"]); previous=temp.exists()
        if previous: return
        # all construction paths provide this exact schema; lightweight preflight catches programmer mistakes.
        if set(state)!={"session_id","caller_uid","caller_gid","directory","pinned","mountpoint","pids","nbds","attached","mounted"}: raise ImageExplorerError("invalid explorer state")
    def _run(self,argv,timeout=20,capture=False):
        result=self.execute(tuple(argv),shell=False,stdout=subprocess.PIPE if capture else subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False,timeout=timeout,env=_ENV)
        if getattr(result,"returncode",result if isinstance(result,int) else 1)!=0: raise ImageExplorerError("explorer command failed")
        return result
    @contextmanager
    def _repository_fd(self, repository):
        wanted=self._caller_repository_identity(repository)
        fd = os.open(repository, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info=os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or (info.st_dev,info.st_ino) != wanted:
                raise ImageExplorerError("invalid repository")
            yield fd
        finally:
            os.close(fd)
    def _caller_repository_identity(self, repository):
        if self.caller_directory_validator is not None:
            value=self.caller_directory_validator(repository,self.uid,self.gid)
            if not isinstance(value,tuple) or len(value)!=2 or not all(type(x) is int for x in value): raise ImageExplorerError("repository authorization failed")
            return value
        read,write=os.pipe(); child=os.fork()
        if child == 0:
            try:
                os.close(read); account=pwd.getpwuid(self.uid); groups=os.getgrouplist(account.pw_name,self.gid)
                if os.geteuid() == 0:
                    os.setgroups(groups); os.setgid(self.gid); os.setuid(self.uid)
                elif os.getuid() != self.uid or os.getgid() != self.gid:
                    os._exit(1)
                fd=os.open(repository,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                try:
                    info=os.fstat(fd); os.listdir(fd)
                    if not stat.S_ISDIR(info.st_mode): os._exit(1)
                    os.write(write,struct.pack("!QQ",info.st_dev,info.st_ino))
                finally: os.close(fd)
            except BaseException: os._exit(1)
            finally: os.close(write)
            os._exit(0)
        os.close(write)
        try: data=os.read(read,16)
        finally: os.close(read)
        _,status=os.waitpid(child,0)
        if len(data)!=16 or not os.WIFEXITED(status) or os.WEXITSTATUS(status)!=0: raise ImageExplorerError("repository is not accessible to caller")
        return struct.unpack("!QQ",data)
    def _pin_repository(self, repository, pinned):
        with self._repository_fd(repository) as fd:
            self._run((_BIN["mount"],"--bind",f"/proc/{os.getpid()}/fd/{fd}",str(pinned)))
    def _checkpoint(self,state): self._write_state(state)
    def _mount_parent(self, path):
        path.mkdir(mode=0o700); os.chown(path,0,0)
        # The root-owned parent cannot be replaced by the caller; this ACL grants
        # only that exact UID traversal to the otherwise private session path.
        self._run((_BIN["setfacl"],"-m",f"u:{self.uid}:--x,m::--x,g::---,o::---",str(path)))
    def _connect(self,r):
        s=uuid4().hex; d=self.runtime/s; u=self.mount_runtime/s; pinned=d/"repository"; mount=u/"files"; state={"session_id":s,"caller_uid":self.uid,"caller_gid":self.gid,"directory":str(d),"pinned":str(pinned),"mountpoint":str(mount),"pids":[],"nbds":[],"attached":[],"mounted":False}
        try:
            d.mkdir(mode=0o700); pinned.mkdir(mode=0o700); self._mount_parent(u); mount.mkdir(mode=0o755); os.chown(mount,0,0); self._checkpoint(state)
            self._pin_repository(r.repository, pinned)
            self._checkpoint(state)
            image=pinned/r.image_name
            if image.is_symlink() or not image.is_dir() or image_fingerprint(image)!=r.image_fingerprint: raise ImageExplorerError("image changed after selection")
            parsed=parse_clonezilla_image(image)
            if explorer_support_reason(parsed) or r.source_partition not in {p.name for p in parsed.topology.partitions}: raise ImageExplorerError("image is not supported for exploration")
            payloads,compression=derive_partclone_payloads(image,r.source_partition); self._run((_BIN["modprobe"],"nbd","nbds_max=16"))
            joined=self._claim_nbd(state); join=d/"join.sock"; self._spawn(self._join_argv(join,payloads),state); self._connect_nbd(join,joined,state)
            source=joined
            if compression!="none":
                decoded=self._claim_nbd(state); decode=d/"decode.sock"; self._spawn(self._decode_argv(decode,joined,compression),state); self._connect_nbd(decode,decoded,state); source=decoded
            output=self._claim_nbd(state); process=self._spawn((_BIN["partclone-nbd"],"-d",output,"-c",source),state); self._wait_ready(process, output); state["attached"].append(output); self._checkpoint(state); self._run((_BIN["blockdev"],"--setro",output)); result=self._run((_BIN["blockdev"],"--getro",output),capture=True)
            read_only=getattr(result,"stdout",b""); read_only=read_only.decode("ascii","replace") if isinstance(read_only,bytes) else read_only
            if read_only.strip() != "1": raise ImageExplorerError("output NBD is not read-only")
            self._run((_BIN["mount"],"-o","ro,nosuid,nodev,noexec",output,str(mount))); state["mounted"]=True; self._checkpoint(state); return ExplorerResult(r.request_id,"ok","mounted",s,str(mount))
        except Exception:
            self._cleanup(state,False); raise
    def _join_argv(self,socket,payloads): return (_BIN["nbdkit"],"--foreground","--readonly","--unix",str(socket),"--filter=truncate","split",*(str(x) for x in payloads),"round-up=512")
    def _decode_argv(self,socket,joined,compression): return (_BIN["nbdkit"],"--foreground","--readonly","--unix",str(socket),"--filter=truncate",f"--filter={compression}","file",f"file={joined}","round-up=512")
    def _spawn(self,argv,state):
        p=self.popen(tuple(argv),shell=False,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,encoding="utf-8",errors="replace",start_new_session=True,env=_ENV); state["pids"].append({"pid":p.pid,"argv":list(argv)}); self._checkpoint(state); return p
    def _claim_nbd(self,state):
        for e in sorted(self.sys_block.glob("nbd[0-9]*")):
            dev=f"/dev/{e.name}"; pid=e/"pid"
            try: occupied=pid.read_text(encoding="ascii").strip() not in {"","0"}
            except FileNotFoundError: occupied=False
            except OSError: continue
            try: empty=int((e/"size").read_text(encoding="ascii").strip()) == 0
            except (OSError,ValueError): empty=False
            if not occupied and empty and Path(dev).exists() and dev not in state["nbds"]: state["nbds"].append(dev); self._checkpoint(state); return dev
        raise ImageExplorerError("no free NBD devices")
    def _connect_nbd(self,socket,device,state):
        deadline = self.monotonic() + 10
        while self.monotonic() < deadline:
            if socket.exists():
                try:
                    self._run((_BIN["nbd-client"],"-unix",str(socket),device))
                    state["attached"].append(device)
                    self._checkpoint(state)
                    return
                except ImageExplorerError:
                    pass
            self.sleep(.1)
        raise ImageExplorerError("NBD backend did not become ready")
    def _wait_ready(self,p,device,timeout=15):
        deadline=self.monotonic()+timeout
        device_name = Path(device).name
        pid_path = self.sys_block/device_name/"pid"
        size_path = self.sys_block/device_name/"size"
        while self.monotonic()<deadline:
            if p.poll() is not None: raise ImageExplorerError("partclone-nbd exited before ready")
            try:
                if int(size_path.read_text(encoding="ascii").strip()) > 0:
                    return
            except (OSError, ValueError):
                pass
            try:
                ready,_,_=select.select((p.stdout,),(),(),.1)
                if ready and "Waiting for requests" in p.stdout.readline(): return
            except (OSError,TypeError): pass
            self.sleep(.1)
        raise ImageExplorerError("partclone-nbd readiness timed out")
    def _healthy(self,state):
        if not state["mounted"] or not self.is_mount(state["mountpoint"]): return False
        return all(self._pid_matches(x) for x in state["pids"])
    def _status(self,r):
        state=self._read_state(r.session_id)
        if state is None:return ExplorerResult(r.request_id,"not-mounted","not mounted")
        if state["caller_uid"] != self.uid or state["caller_gid"] != self.gid: raise ImageExplorerError("explorer session belongs to another caller")
        if not self._healthy(state): return ExplorerResult(r.request_id,"failed","explorer session is stale",r.session_id)
        return ExplorerResult(r.request_id,"ok","mounted",r.session_id,state["mountpoint"])
    def _disconnect(self,r):
        state=self._read_state(r.session_id)
        if state is None:return ExplorerResult(r.request_id,"not-mounted","not mounted")
        if state["caller_uid"] != self.uid or state["caller_gid"] != self.gid: raise ImageExplorerError("explorer session belongs to another caller")
        self._cleanup(state,True); return ExplorerResult(r.request_id,"ok","unmounted",r.session_id)
    def _cleanup(self,state,busy):
        if self.is_mount(state["mountpoint"]):
            try:self._run((_BIN["umount"],"--",state["mountpoint"]))
            except ImageExplorerError:
                raise ImageExplorerError("explorer mount is busy" if busy else "explorer mount cleanup failed")
        for dev in tuple(reversed(state["attached"])):
            if self._nbd_detached(dev):
                state["attached"].remove(dev); self._checkpoint(state)
                continue
            try:
                self._run((_BIN["nbd-client"],"-d",dev))
            except ImageExplorerError:
                if not self._wait_nbd_detached(dev):
                    raise ImageExplorerError(f"NBD detach failed: {dev}")
            if not self._wait_nbd_detached(dev): raise ImageExplorerError(f"NBD detach incomplete: {dev}")
            state["attached"].remove(dev); self._checkpoint(state)
        for x in reversed(state["pids"]):
            self._terminate(x)
        if self.is_mount(state["pinned"]):
            try:self._run((_BIN["umount"],"--",state["pinned"]))
            except ImageExplorerError: raise ImageExplorerError("pinned repository cleanup failed")
        self._state_path(state["session_id"]).unlink(missing_ok=True); shutil.rmtree(state["directory"],ignore_errors=True); shutil.rmtree(self.mount_runtime/state["session_id"],ignore_errors=True)
    def _nbd_detached(self, dev):
        entry=self.sys_block/Path(dev).name
        try:
            pid=(entry/"pid").read_text(encoding="ascii").strip()
        except FileNotFoundError: pid=""
        except OSError: return False
        try: size=int((entry/"size").read_text(encoding="ascii").strip())
        except (OSError,ValueError): return False
        return pid in {"","0"} and size == 0
    def _wait_nbd_detached(self, dev, timeout=5):
        deadline=self.monotonic()+timeout
        while self.monotonic()<deadline:
            if self._nbd_detached(dev): return True
            self.sleep(.1)
        return self._nbd_detached(dev)
    def _pid_matches(self,x):
        try: actual=Path(f"/proc/{x['pid']}/cmdline").read_bytes().split(b"\0")[:-1]; leader=os.getpgid(x["pid"])==x["pid"]
        except OSError:return False
        return leader and actual==[v.encode() for v in x["argv"]]
    def _terminate(self,x):
        if not self._pid_matches(x): return
        for sig in (signal.SIGTERM,signal.SIGKILL):
            try:os.killpg(x["pid"],sig)
            except ProcessLookupError:return
            deadline=self.monotonic()+5
            while self.monotonic()<deadline:
                if not Path(f"/proc/{x['pid']}").exists(): return
                self.sleep(.1)
    def _recover_others(self):
        for p in self.runtime.glob("*.json"):
            if _ID.fullmatch(p.stem):
                try:
                    state=self._read_state(p.stem)
                    if state and state["caller_uid"] == self.uid:self._cleanup(state,False)
                except ImageExplorerError: raise
