from typing import Optional
import sqlite3, json, hashlib, secrets, re, os
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

DB = os.environ.get("VMS_DB", "vms.db")
MENU = {
 "Administration": ["Sites","Security Settings",["Identity Access",["User Types","Users","Groups"]],"Reports","Auxiliaries","License","E-Sign Config","Approval Configuration","E-Mail Config","File Server Configuration","ID Generation","Accreditation Number","External Integrations","API Mapping"],
 "Master Data": ["Building Blocks","Document Templates","Checklists","Entities","Projects","Validation Type","System & Asset Master","Requirement Library","Test Case Library","Automation Configuration","Risk Categories","Execution Status / Result Values","Report Templates"],
 "Document Management": ["Document Initiation","Document Creation","Document Draft Review","Document Approval","Document Training Record","Document for Effective","Document Request","Document Issuance","Document Retrieval","Document Obsolete","Archival","Document Location","My Documents","Document Reports"],
 "Validation Management": ["Validation Project Registration","Scope & Module Selection","Validation Plan","Requirement & Risk Traceability","Test Case Preparation","Protocol Review & Approval","Release for Testing"],
 "Validation Execution": ["Execution Assignment","Manual Execution","Automation Mapping & Configuration","Run Validation","Execution Monitoring","Results & Evidence","Execution Review","Final Execution Approval"],
 "Defect Management": ["Defect Registration","Defect Classification & Assignment","Investigation & Resolution","Retest & Verification","Defect Closure","Defect Reports"],
 "Evidence & Audit Trail": ["Evidence Repository","Evidence Review","Audit Trail","Audit Reports"],
 "OQ & Reports": ["OQ Protocol Generation","OQ Execution Report","Traceability / Coverage Report","Test Results & Deviation Report","Validation Summary Report","Report Review & Approval","Approved Report Repository","Project Closure"],
 "Periodic Review": ["Review Schedule","Periodic Review Registration","System Change Assessment","Review & Approval","Periodic Review Reports"],
}
slug = lambda s: re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
def flat():
    for mod, items in MENU.items():
        for i in items:
            for x in (i[1] if isinstance(i, list) else [i]):
                yield mod, x
RES = {slug(x): (m, x) for m, x in flat()}
# controlled relationships: child resource -> parent resource (parent must be Approved/Effective)
LINKS = {"document-creation":"document-templates","validation-plan":"projects","scope-module-selection":"validation-project-registration",
 "requirement-risk-traceability":"requirement-library","test-case-preparation":"test-case-library","protocol-review-approval":"test-case-preparation",
 "release-for-testing":"protocol-review-approval","execution-assignment":"release-for-testing","manual-execution":"execution-assignment",
 "run-validation":"automation-configuration","results-evidence":"manual-execution","defect-registration":"results-evidence",
 "defect-classification-assignment":"defect-registration","investigation-resolution":"defect-classification-assignment",
 "retest-verification":"investigation-resolution","defect-closure":"retest-verification","oq-protocol-generation":"report-templates",
 "oq-execution-report":"oq-protocol-generation","validation-summary-report":"oq-execution-report","periodic-review-registration":"review-schedule",
 "system-change-assessment":"periodic-review-registration","review-approval":"system-change-assessment"}
FLOW = {"Draft":["In Review"],"In Review":["Approved","Draft"],"Approved":["Effective"],"Effective":["Obsolete"],"Obsolete":[]}
TROLE = {"In Review":{"author","admin"},"Approved":{"approver","admin"},"Draft":{"reviewer","approver","admin"},"Effective":{"approver","admin"},"Obsolete":{"approver","admin"}}
ESIGN = {"Approved":"Approved","Effective":"Released for use","Obsolete":"Retired"}

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c
now = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
H = lambda s: hashlib.sha256(s.encode()).hexdigest()
def init():
    c = db()
    c.executescript("""CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY,pw TEXT,role TEXT,name TEXT);
    CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY,res TEXT,code TEXT,title TEXT,description TEXT,status TEXT,link_id INTEGER,version INTEGER DEFAULT 1,created_by TEXT,created_at TEXT,updated_at TEXT,comment TEXT);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,ts TEXT,user TEXT,action TEXT,res TEXT,rec_id INTEGER,detail TEXT,prev TEXT,hash TEXT);
    CREATE TABLE IF NOT EXISTS esign(id INTEGER PRIMARY KEY,rec_id INTEGER,res TEXT,user TEXT,meaning TEXT,ts TEXT,rec_hash TEXT);""")
    if not c.execute("SELECT 1 FROM users").fetchone():
        for u, r in [("admin","admin"),("author","author"),("reviewer","reviewer"),("approver","approver")]:
            c.execute("INSERT INTO users VALUES(?,?,?,?)", (u, H("Vms@123"), r, u.title()))
    c.commit(); c.close()
init()

def log(c, user, action, res, rid, detail):
    p = c.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
    prev = p["hash"] if p else "0"*64; ts = now()
    c.execute("INSERT INTO audit(ts,user,action,res,rec_id,detail,prev,hash) VALUES(?,?,?,?,?,?,?,?)",
              (ts, user, action, res, rid, detail, prev, H(prev+ts+user+action+res+str(rid)+detail)))
TOK = {}
def auth(t):
    u = TOK.get((t or "").replace("Bearer ", ""))
    if not u: raise HTTPException(401, "Not authenticated")
    return u
def check_res(res):
    if res not in RES: raise HTTPException(404, "Unknown menu")
def can_write(u, res):
    if RES[res][0] == "Administration": return u["role"] == "admin"
    if RES[res][0] == "Master Data": return u["role"] in ("admin","author")
    return u["role"] in ("admin","author")

app = FastAPI(title="Lab Iconics VMS")
class Login(BaseModel): username: str; password: str
class Rec(BaseModel): title: str; description: str = ""; link_id: Optional[int] = None
class Trans(BaseModel): to: str; password: str = ""; comment: str = ""

@app.post("/api/login")
def login(b: Login):
    c = db(); u = c.execute("SELECT * FROM users WHERE username=? AND pw=?", (b.username, H(b.password))).fetchone()
    if not u: raise HTTPException(401, "Invalid credentials")
    t = secrets.token_hex(16); TOK[t] = dict(u); log(c, u["username"], "LOGIN", "auth", 0, ""); c.commit()
    return {"token": t, "user": {"username": u["username"], "role": u["role"], "name": u["name"]}}

@app.get("/api/menu")
def menu(authorization: str = Header(None)):
    auth(authorization)
    return [{"module": m, "items": [{"label": i[0], "children": [{"label": x, "res": slug(x)} for x in i[1]]} if isinstance(i, list) else {"label": i, "res": slug(i)} for i in items]} for m, items in MENU.items()]

@app.get("/api/approvals")
def approvals(authorization: str = Header(None)):
    auth(authorization); c = db()
    return [dict(r, menu=RES[r["res"]][1]) for r in c.execute("SELECT * FROM records WHERE status='In Review' OR comment LIKE 'Reverted:%' ORDER BY updated_at DESC")]

@app.get("/api/audit/verify")
def verify(authorization: str = Header(None)):
    auth(authorization); prev = "0"*64
    for a in db().execute("SELECT * FROM audit ORDER BY id"):
        if a["prev"] != prev or a["hash"] != H(prev+a["ts"]+a["user"]+a["action"]+a["res"]+str(a["rec_id"])+a["detail"]):
            return {"valid": False, "broken_at": a["id"]}
        prev = a["hash"]
    return {"valid": True}

@app.get("/api/audit")
def audit(authorization: str = Header(None)):
    auth(authorization); return [dict(a) for a in db().execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200")]

@app.get("/api/{res}")
def lst(res: str, q: str = "", status: str = "", sort: str = "updated_at", desc: bool = True, page: int = 1, size: int = 10, authorization: str = Header(None)):
    auth(authorization); check_res(res)
    sort = sort if sort in ("code","title","status","created_by","updated_at") else "updated_at"
    w, p = "res=?", [res]
    if q: w += " AND (code LIKE ? OR title LIKE ? OR description LIKE ?)"; p += [f"%{q}%"]*3
    if status: w += " AND status=?"; p.append(status)
    c = db(); total = c.execute(f"SELECT COUNT(*) n FROM records WHERE {w}", p).fetchone()["n"]
    rows = c.execute(f"SELECT * FROM records WHERE {w} ORDER BY {sort} {'DESC' if desc else 'ASC'} LIMIT ? OFFSET ?", p+[size,(page-1)*size]).fetchall()
    return {"total": total, "parent": LINKS.get(res), "items": [dict(r) for r in rows]}

def need_parent(c, res, link_id):
    par = LINKS.get(res)
    if not par: return
    r = c.execute("SELECT status FROM records WHERE id=? AND res=?", (link_id, par)).fetchone() if link_id else None
    if not r: raise HTTPException(422, f"A linked record from '{RES[par][1]}' is required")
    if r["status"] not in ("Approved","Effective"): raise HTTPException(422, f"Linked {RES[par][1]} record must be Approved or Effective")

@app.post("/api/{res}")
def create(res: str, b: Rec, authorization: str = Header(None)):
    u = auth(authorization); check_res(res)
    if not can_write(u, res): raise HTTPException(403, "Not permitted")
    if not b.title.strip(): raise HTTPException(422, "Title is required")
    c = db(); need_parent(c, res, b.link_id)
    n = c.execute("SELECT COUNT(*) n FROM records WHERE res=?", (res,)).fetchone()["n"] + 1
    code = "".join(w[0] for w in RES[res][1].split() if w[0].isalnum()).upper()[:4] + f"-{n:04d}"
    cur = c.execute("INSERT INTO records(res,code,title,description,status,link_id,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (res, code, b.title, b.description, "Draft", b.link_id, u["username"], now(), now()))
    log(c, u["username"], "CREATE", res, cur.lastrowid, code); c.commit(); return {"id": cur.lastrowid, "code": code}

@app.put("/api/{res}/{rid}")
def update(res: str, rid: int, b: Rec, authorization: str = Header(None)):
    u = auth(authorization); check_res(res); c = db()
    r = c.execute("SELECT * FROM records WHERE id=? AND res=?", (rid, res)).fetchone()
    if not r: raise HTTPException(404, "Not found")
    if not can_write(u, res): raise HTTPException(403, "Not permitted")
    if r["status"] != "Draft": raise HTTPException(409, "Only Draft records can be edited; locked after submission")
    need_parent(c, res, b.link_id)
    c.execute("UPDATE records SET title=?,description=?,link_id=?,updated_at=?,comment='' WHERE id=?", (b.title, b.description, b.link_id, now(), rid))
    log(c, u["username"], "UPDATE", res, rid, r["code"]); c.commit(); return {"ok": True}

@app.post("/api/{res}/{rid}/transition")
def transition(res: str, rid: int, b: Trans, authorization: str = Header(None)):
    u = auth(authorization); check_res(res); c = db()
    r = c.execute("SELECT * FROM records WHERE id=? AND res=?", (rid, res)).fetchone()
    if not r: raise HTTPException(404, "Not found")
    if b.to not in FLOW[r["status"]]: raise HTTPException(409, f"Cannot move from {r['status']} to {b.to}: mandatory stages cannot be skipped")
    if u["role"] not in TROLE[b.to]: raise HTTPException(403, "Your role cannot perform this step")
    if r["created_by"] == u["username"] and b.to in ("Approved","Effective") and u["role"] != "admin": raise HTTPException(403, "Author cannot approve own record")
    if b.to == "Draft" and not b.comment.strip(): raise HTTPException(422, "A reason is required to revert")
    if b.to in ESIGN:
        if H(b.password) != c.execute("SELECT pw FROM users WHERE username=?", (u["username"],)).fetchone()["pw"]:
            raise HTTPException(401, "E-signature re-authentication failed")
        c.execute("INSERT INTO esign(rec_id,res,user,meaning,ts,rec_hash) VALUES(?,?,?,?,?,?)", (rid, res, u["username"], ESIGN[b.to], now(), H(json.dumps(dict(r), sort_keys=True))))
    cm = f"Reverted: {b.comment}" if b.to == "Draft" else ""
    c.execute("UPDATE records SET status=?,comment=?,updated_at=? WHERE id=?", (b.to, cm, now(), rid))
    log(c, u["username"], f"{r['status']} -> {b.to}", res, rid, b.comment); c.commit(); return {"status": b.to}

@app.get("/api/{res}/{rid}/history")
def history(res: str, rid: int, authorization: str = Header(None)):
    auth(authorization); c = db()
    return {"audit": [dict(a) for a in c.execute("SELECT ts,user,action,detail,hash FROM audit WHERE res=? AND rec_id=? ORDER BY id", (res, rid))],
            "signatures": [dict(s) for s in c.execute("SELECT user,meaning,ts,rec_hash FROM esign WHERE res=? AND rec_id=? ORDER BY id", (res, rid))]}

@app.get("/")
def index(): return FileResponse("static/index.html")
app.mount("/static", StaticFiles(directory="static"), name="static")

# ================= Execution, evidence, defects, reports =================
import base64, html as _html
EVD = "evidence"; os.makedirs(EVD, exist_ok=True)
_c = db(); _c.executescript("""CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY,rec_id INTEGER,code TEXT,executor TEXT,status TEXT,started TEXT,completed TEXT,retest_of INTEGER);
CREATE TABLE IF NOT EXISTS steps(id INTEGER PRIMARY KEY,run_id INTEGER,n INTEGER,instruction TEXT,expected TEXT,ev_req INTEGER,result TEXT,actual TEXT,comment TEXT,ev_file TEXT,ev_name TEXT,ev_hash TEXT,done_by TEXT,ts TEXT);
CREATE TABLE IF NOT EXISTS defects(id INTEGER PRIMARY KEY,code TEXT,run_id INTEGER,step_id INTEGER,title TEXT,description TEXT,status TEXT,created_by TEXT,created_at TEXT,updated_at TEXT,note TEXT);"""); _c.commit(); _c.close()

def parse_steps(text):
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if "|" not in line: continue
        ins, exp = [x.strip() for x in line.split("|", 1)]
        ev = ins.startswith("[E]")
        if ev: ins = ins[3:].strip()
        if ins and exp: out.append((ins, exp, 1 if ev else 0))
    return out
RUNQ = "SELECT runs.*,records.code tc,records.title tc_title FROM runs JOIN records ON records.id=runs.rec_id"
class RunIn(BaseModel): rec_id: int; retest_of: Optional[int] = None
class StepIn(BaseModel): result: str; actual: str = ""; comment: str = ""; file_name: str = ""; file_b64: str = ""
class DefIn(BaseModel): to: str; comment: str = ""

@app.post("/api/x/runs")
def start_run(b: RunIn, authorization: str = Header(None)):
    u = auth(authorization); c = db()
    if u["role"] not in ("author", "admin"): raise HTTPException(403, "Only authors/admins execute tests")
    r = c.execute("SELECT * FROM records WHERE id=? AND res IN ('test-case-library','test-case-preparation')", (b.rec_id,)).fetchone()
    if not r: raise HTTPException(404, "Test case not found")
    if r["status"] not in ("Approved", "Effective"): raise HTTPException(409, "Test case must be approved before execution")
    st = parse_steps(r["description"])
    if not st: raise HTTPException(422, "Test case has no steps. Write one per line: Instruction | Expected result")
    if b.retest_of and not c.execute("SELECT 1 FROM runs WHERE id=? AND rec_id=?", (b.retest_of, b.rec_id)).fetchone(): raise HTTPException(422, "Invalid original run")
    n = c.execute("SELECT COUNT(*) n FROM runs").fetchone()["n"] + 1
    cur = c.execute("INSERT INTO runs(rec_id,code,executor,status,started,retest_of) VALUES(?,?,?,?,?,?)", (b.rec_id, f"RUN-{n:04d}", u["username"], "In Progress", now(), b.retest_of))
    for i, (a, e, v) in enumerate(st, 1): c.execute("INSERT INTO steps(run_id,n,instruction,expected,ev_req) VALUES(?,?,?,?,?)", (cur.lastrowid, i, a, e, v))
    log(c, u["username"], "RUN START", "run", cur.lastrowid, r["code"]); c.commit(); return {"id": cur.lastrowid}

@app.get("/api/x/runs")
def runs(authorization: str = Header(None)):
    auth(authorization); return [dict(r) for r in db().execute(RUNQ + " ORDER BY runs.id DESC")]

@app.get("/api/x/runs/{rid}")
def run_detail(rid: int, authorization: str = Header(None)):
    auth(authorization); c = db(); r = c.execute(RUNQ + " WHERE runs.id=?", (rid,)).fetchone()
    if not r: raise HTTPException(404, "Run not found")
    return {"run": dict(r), "steps": [dict(s) for s in c.execute("SELECT * FROM steps WHERE run_id=? ORDER BY n", (rid,))],
            "defects": [dict(d) for d in c.execute("SELECT * FROM defects WHERE run_id=?", (rid,))]}

@app.post("/api/x/steps/{sid}/result")
def step_result(sid: int, b: StepIn, authorization: str = Header(None)):
    u = auth(authorization); c = db()
    s = c.execute("SELECT * FROM steps WHERE id=?", (sid,)).fetchone()
    if not s: raise HTTPException(404, "Step not found")
    run = c.execute("SELECT * FROM runs WHERE id=?", (s["run_id"],)).fetchone()
    if run["status"] != "In Progress": raise HTTPException(409, "Run is already completed")
    if run["executor"] != u["username"] and u["role"] != "admin": raise HTTPException(403, "Only the assigned executor can record results")
    if s["result"]: raise HTTPException(409, "Result already recorded and cannot be overwritten. Start a retest to correct it")
    if b.result not in ("Pass", "Fail", "Blocked", "Not Applicable"): raise HTTPException(422, "Invalid result")
    if b.result in ("Pass", "Fail") and not b.actual.strip(): raise HTTPException(422, "Actual result is required")
    if b.result in ("Blocked", "Not Applicable") and not b.comment.strip(): raise HTTPException(422, "A justification comment is required")
    fname = h = ""
    if b.file_b64:
        ext = os.path.splitext(b.file_name.lower())[1]
        if ext not in (".png", ".jpg", ".jpeg", ".pdf", ".txt", ".log", ".csv"): raise HTTPException(422, "File type not allowed")
        try: raw = base64.b64decode(b.file_b64)
        except Exception: raise HTTPException(422, "Invalid file")
        if len(raw) > 5_000_000: raise HTTPException(422, "File larger than 5 MB")
        h = hashlib.sha256(raw).hexdigest(); fname = f"{sid}_{h[:12]}{ext}"
        with open(os.path.join(EVD, fname), "wb") as f: f.write(raw)
    if s["ev_req"] and b.result in ("Pass", "Fail") and not fname: raise HTTPException(422, "Evidence is mandatory for this step")
    c.execute("UPDATE steps SET result=?,actual=?,comment=?,ev_file=?,ev_name=?,ev_hash=?,done_by=?,ts=? WHERE id=?", (b.result, b.actual, b.comment, fname, b.file_name, h, u["username"], now(), sid))
    log(c, u["username"], "STEP " + b.result.upper(), "run", run["id"], f"step {s['n']}")
    if b.result == "Fail":
        n = c.execute("SELECT COUNT(*) n FROM defects").fetchone()["n"] + 1
        c.execute("INSERT INTO defects(code,run_id,step_id,title,description,status,created_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                  (f"DEF-{n:04d}", run["id"], sid, f"Step {s['n']}: {s['instruction']}"[:120], f"Expected: {s['expected']}\nActual: {b.actual}", "Open", u["username"], now(), now()))
        log(c, u["username"], "DEFECT CREATED", "defect", n, f"DEF-{n:04d}")
    c.commit(); return {"ok": True}

@app.get("/api/x/evidence/{sid}")
def evidence(sid: int, authorization: str = Header(None)):
    auth(authorization); s = db().execute("SELECT ev_file,ev_name FROM steps WHERE id=?", (sid,)).fetchone()
    if not s or not s["ev_file"]: raise HTTPException(404, "No evidence")
    return FileResponse(os.path.join(EVD, s["ev_file"]), filename=s["ev_name"])

@app.post("/api/x/runs/{rid}/complete")
def complete(rid: int, authorization: str = Header(None)):
    u = auth(authorization); c = db(); run = c.execute("SELECT * FROM runs WHERE id=?", (rid,)).fetchone()
    if not run: raise HTTPException(404, "Run not found")
    if run["status"] != "In Progress": raise HTTPException(409, "Run is already completed")
    if run["executor"] != u["username"] and u["role"] != "admin": raise HTTPException(403, "Only the executor can complete the run")
    res = [s["result"] for s in c.execute("SELECT result FROM steps WHERE run_id=?", (rid,))]
    if any(not x for x in res): raise HTTPException(422, f"{sum(1 for x in res if not x)} step(s) still have no result")
    st = "Passed" if all(x in ("Pass", "Not Applicable") for x in res) else "Failed"
    c.execute("UPDATE runs SET status=?,completed=? WHERE id=?", (st, now(), rid)); log(c, u["username"], "RUN " + st.upper(), "run", rid, ""); c.commit(); return {"status": st}

DFLOW = {"Open": ["Investigating"], "Investigating": ["Resolved"], "Resolved": ["Closed", "Investigating"]}
DROLE = {"Investigating": {"reviewer", "approver", "admin"}, "Resolved": {"author", "admin"}, "Closed": {"approver", "admin"}}
@app.get("/api/x/defects")
def defects(authorization: str = Header(None)):
    auth(authorization)
    return [dict(d) for d in db().execute("SELECT defects.*,runs.code run_code,runs.rec_id FROM defects JOIN runs ON runs.id=defects.run_id ORDER BY defects.id DESC")]

@app.post("/api/x/defects/{did}/transition")
def defect_t(did: int, b: DefIn, authorization: str = Header(None)):
    u = auth(authorization); c = db(); d = c.execute("SELECT * FROM defects WHERE id=?", (did,)).fetchone()
    if not d: raise HTTPException(404, "Defect not found")
    if b.to not in DFLOW.get(d["status"], []): raise HTTPException(409, f"Cannot move from {d['status']} to {b.to}")
    if u["role"] not in DROLE[b.to]: raise HTTPException(403, "Your role cannot perform this step")
    if not b.comment.strip(): raise HTTPException(422, "A comment is required")
    if b.to == "Closed":
        n = c.execute("SELECT n FROM steps WHERE id=?", (d["step_id"],)).fetchone()["n"]
        if not c.execute("SELECT 1 FROM runs r JOIN steps s ON s.run_id=r.id WHERE r.retest_of=? AND s.n=? AND s.result='Pass'", (d["run_id"], n)).fetchone():
            raise HTTPException(409, "Closure needs a retest run with this step passing")
    c.execute("UPDATE defects SET status=?,note=?,updated_at=? WHERE id=?", (b.to, b.comment, now(), did))
    log(c, u["username"], f"DEFECT {d['status']} -> {b.to}", "defect", did, b.comment); c.commit(); return {"status": b.to}

@app.get("/api/x/report/{rid}")
def report(rid: int, authorization: str = Header(None)):
    auth(authorization); c = db(); r = c.execute(RUNQ + " WHERE runs.id=?", (rid,)).fetchone()
    if not r: raise HTTPException(404, "Run not found")
    e = lambda x: _html.escape(str(x if x is not None else ""))
    rows = "".join(f"<tr><td>{s['n']}<td>{e(s['instruction'])}{' [E]' if s['ev_req'] else ''}<td>{e(s['expected'])}<td>{e(s['actual'])}<td><b>{e(s['result'] or 'Not executed')}</b><td>{e(s['comment'])}<td>{e(s['ev_name'])}<br><small>{e((s['ev_hash'] or '')[:16])}</small><td>{e(s['done_by'])}<br><small>{e(s['ts'])}</small></tr>" for s in c.execute("SELECT * FROM steps WHERE run_id=? ORDER BY n", (rid,)))
    dr = "".join(f"<tr><td>{e(d['code'])}<td>{e(d['title'])}<td>{e(d['status'])}<td>{e(d['note'])}</tr>" for d in c.execute("SELECT * FROM defects WHERE run_id=?", (rid,)))
    rt = "".join(f"<tr><td>{e(x['code'])}<td>{e(x['status'])}<td>{e(x['executor'])}<td>{e(x['completed'])}</tr>" for x in c.execute("SELECT * FROM runs WHERE retest_of=?", (rid,)))
    sg = "".join(f"<tr><td>{e(x['user'])}<td>{e(x['meaning'])}<td>{e(x['ts'])}</tr>" for x in c.execute("SELECT * FROM esign WHERE rec_id=? AND res IN ('test-case-library','test-case-preparation')", (r["rec_id"],)))
    css = "<style>body{font-family:Arial;font-size:12px}table{border-collapse:collapse;width:100%;margin-bottom:14px}td,th{border:1px solid #999;padding:5px;text-align:left;vertical-align:top}th{background:#405945;color:#fff}</style>"
    return {"html": f"{css}<h2>Execution Report {e(r['code'])}</h2><p>Test case: {e(r['tc'])} – {e(r['tc_title'])}<br>Executor: {e(r['executor'])}<br>Outcome: <b>{e(r['status'])}</b><br>Started: {e(r['started'])} | Completed: {e(r['completed'])}<br>Retest of run: {e(r['retest_of'] or 'n/a')}<br>Generated: {now()}</p><h3>Steps</h3><table><tr><th>#<th>Instruction<th>Expected<th>Actual<th>Result<th>Comment<th>Evidence<th>By</tr>{rows}</table><h3>Defects</h3><table><tr><th>ID<th>Title<th>Status<th>Note</tr>{dr}</table><h3>Retests</h3><table><tr><th>Run<th>Outcome<th>Executor<th>Completed</tr>{rt}</table><h3>Test case approvals (e-signatures)</h3><table><tr><th>Signer<th>Meaning<th>Time</tr>{sg}</table>"}
