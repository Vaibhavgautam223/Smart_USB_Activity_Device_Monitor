import os, hmac, json, secrets, re
from functools import wraps
from flask import Flask, abort, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from database import get_db, init_db, get_setting, set_setting
from monitor import USBMonitor
import enforcement

app=Flask(__name__)
app.secret_key=os.getenv("SECRET_KEY","change-this-secret-key")
init_db()
monitor=USBMonitor()
monitor.start()

STATUS_FILTERS={"pending","authorized","blocked"}

def login_required(fn):
    @wraps(fn)
    def wrapper(*args,**kwargs):
        if "admin_id" not in session: return redirect(url_for("login"))
        return fn(*args,**kwargs)
    return wrapper

# ---- Registration (always open) ----
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{3,50}$")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""

        error = None
        if not USERNAME_RE.match(username):
            error = "Username must be 3-50 chars: letters, digits, dot, dash, underscore."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm:
            error = "Passwords do not match."

        if not error:
            db = get_db(); cur = db.cursor(dictionary=True)
            try:
                cur.execute("SELECT id FROM admins WHERE username=%s", (username,))
                if cur.fetchone():
                    error = "That username is already taken."
                else:
                    cur.execute(
                        "INSERT INTO admins(username,password_hash) VALUES(%s,%s)",
                        (username, generate_password_hash(password)),
                    )
                    db.commit()
            finally:
                cur.close(); db.close()

        if error:
            flash(error, "danger")
            return render_template("register.html", username=username)

        flash("Account created. Please sign in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", username="")

# ---- CSRF ----
@app.before_request
def csrf_protect():
    if request.method=="POST":
        sent=request.form.get("csrf_token","")
        expected=session.get("csrf_token","")
        if not expected or not hmac.compare_digest(sent,expected):
            abort(400,"Form expired. Go back, refresh the page and try again.")

@app.context_processor
def inject_globals():
    if "csrf_token" not in session: session["csrf_token"]=secrets.token_hex(16)
    return {"csrf_token":session["csrf_token"],"is_admin_process":enforcement.is_admin()}

@app.route("/")
def index(): return redirect(url_for("dashboard") if session.get("admin_id") else url_for("login"))

@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        db=get_db(); cur=db.cursor(dictionary=True)
        cur.execute("SELECT * FROM admins WHERE username=%s",(request.form.get("username","").strip(),))
        user=cur.fetchone(); cur.close(); db.close()
        if user and check_password_hash(user["password_hash"],request.form.get("password","")):
            token=session.get("csrf_token")
            session.clear(); session["csrf_token"]=token or secrets.token_hex(16)
            session["admin_id"]=user["id"]; session["username"]=user["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.","danger")
    return render_template("login.html")

@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    db=get_db(); cur=db.cursor(dictionary=True)
    cur.execute("""SELECT COUNT(*) total, SUM(connected=1) connected, SUM(connected=0) disconnected,
                   SUM(auth_status='pending') pending, SUM(is_blocked=1) blocked FROM usb_devices""")
    stats=cur.fetchone()
    cur.execute("SELECT * FROM usb_devices WHERE auth_status='pending' ORDER BY last_seen DESC LIMIT 8")
    pending=cur.fetchall()
    cur.execute("SELECT * FROM usb_devices ORDER BY last_seen DESC LIMIT 8")
    devices=cur.fetchall()
    cur.execute("SELECT * FROM usb_events ORDER BY event_time DESC LIMIT 12")
    events=cur.fetchall()
    cur.close(); db.close()
    return render_template("dashboard.html",stats=stats,pending=pending,devices=devices,events=events,
                           mode=get_setting("enforcement_mode","monitor"))

@app.route("/devices")
@login_required
def devices():
    q=request.args.get("q","").strip()
    status=request.args.get("status","")
    where,args=[],[]
    if q:
        like=f"%{q}%"
        where.append("(device_name LIKE %s OR device_id LIKE %s OR manufacturer LIKE %s)"); args+=[like,like,like]
    if status in STATUS_FILTERS:
        where.append("auth_status=%s"); args.append(status)
    sql="SELECT * FROM usb_devices"+(" WHERE "+" AND ".join(where) if where else "")+" ORDER BY last_seen DESC"
    db=get_db(); cur=db.cursor(dictionary=True)
    cur.execute(sql,args)
    rows=cur.fetchall(); cur.close(); db.close()
    return render_template("devices.html",devices=rows,q=q,status=status)

def _back():
    back=request.form.get("back")
    return back if back in (url_for("dashboard"),url_for("devices")) else url_for("devices")

def _decide(device_id,new_status):
    """Record the admin's decision. The monitor thread does the actual enable/disable within a few seconds."""
    db=get_db(); cur=db.cursor(dictionary=True)
    cur.execute("SELECT * FROM usb_devices WHERE id=%s",(device_id,))
    dev=cur.fetchone()
    if not dev:
        cur.close(); db.close(); abort(404)
    cur.execute("UPDATE usb_devices SET auth_status=%s,decided_by=%s,decided_at=NOW() WHERE id=%s",
                (new_status,session["username"],device_id))
    event={"authorized":"AUTHORIZED","blocked":"DENIED"}.get(new_status,"RESET")
    cur.execute("INSERT INTO usb_events(device_id,device_name,event_type,details) VALUES(%s,%s,%s,%s)",
                (dev["device_id"],dev["device_name"],event,json.dumps({"message":f"Set to {new_status} by {session['username']}"})))
    db.commit(); cur.close(); db.close()
    return dev

@app.post("/devices/<int:device_id>/authorize")
@login_required
def authorize_device(device_id):
    dev=_decide(device_id,"authorized")
    if dev["is_blocked"]: flash(f"{dev['device_name']} is authorized and will be re-enabled in a few seconds.","success")
    else: flash(f"{dev['device_name']} is authorized.","success")
    return redirect(_back())

@app.post("/devices/<int:device_id>/block")
@login_required
def block_device(device_id):
    dev=_decide(device_id,"blocked")
    if not enforcement.is_admin():
        flash(f"{dev['device_name']} is marked as blocked, but this app is NOT running as Administrator, so Windows will not disable it. Restart the app from an Administrator terminal.","danger")
    elif dev["connected"]: flash(f"{dev['device_name']} will be blocked in a few seconds.","warning")
    else: flash(f"{dev['device_name']} is blocked. It will be disabled whenever it is plugged in.","warning")
    return redirect(_back())

@app.post("/devices/<int:device_id>/reset")
@login_required
def reset_device(device_id):
    dev=_decide(device_id,"pending")
    flash(f"{dev['device_name']} is back to pending. It follows the protection mode again.","info")
    return redirect(_back())

@app.post("/policy")
@login_required
def set_policy():
    mode=request.form.get("mode")
    if mode not in ("monitor","enforce"): abort(400)
    set_setting("enforcement_mode",mode)
    db=get_db(); cur=db.cursor()
    cur.execute("INSERT INTO usb_events(device_id,device_name,event_type,details) VALUES('SYSTEM','Protection mode','POLICY',%s)",
                (json.dumps({"message":f"Mode set to {mode} by {session['username']}"}),))
    db.commit(); cur.close(); db.close()
    flash("Enforcement is on. Unauthorized USB storage devices will be blocked." if mode=="enforce"
          else "Monitor-only mode. Only devices you blocked stay blocked.","info")
    return redirect(url_for("dashboard"))

@app.route("/events")
@login_required
def events():
    db=get_db(); cur=db.cursor(dictionary=True)
    cur.execute("SELECT * FROM usb_events ORDER BY event_time DESC LIMIT 500")
    rows=cur.fetchall(); cur.close(); db.close()
    return render_template("events.html",events=rows)

@app.route("/api/status")
@login_required
def api_status():
    db=get_db(); cur=db.cursor(dictionary=True)
    cur.execute("""SELECT COUNT(*) total,SUM(connected=1) connected,SUM(connected=0) disconnected,
                   SUM(auth_status='pending') pending,SUM(is_blocked=1) blocked FROM usb_devices""")
    row=cur.fetchone(); cur.close(); db.close()
    return jsonify({k:int(v or 0) for k,v in row.items()})

if __name__=="__main__":
    app.run(host="127.0.0.1",port=int(os.getenv("PORT",5000)),debug=False)