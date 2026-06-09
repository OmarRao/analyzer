"""
VulnBank File Management API
CWE-22, CWE-434, CWE-78, CWE-79, CWE-285 (ATT&CK T1083, T1059, T1190)
WARNING: Intentionally vulnerable.
"""

import os
import subprocess
import hashlib
import random
from flask import Blueprint, request, jsonify, send_file
from models import get_db

files_bp = Blueprint("files", __name__)

BASE_UPLOAD_DIR  = "/var/uploads"
BASE_STORAGE_DIR = "/var/storage"
TEMP_DIR         = "/tmp/vulnbank"

# CWE-798: Hardcoded storage keys
STORAGE_KEY   = "s3-storage-key-hardcoded-here"
CDN_SECRET    = "cdn-secret-token-abcdef"
ENCRYPT_KEY   = "file-encrypt-key-123456"


@files_bp.route("/files/upload", methods=["POST"])
def upload():
    # CWE-434: Unrestricted file upload (ATT&CK T1190)
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file"}), 400
    user_id  = request.form.get("user_id", "")
    category = request.form.get("category", "general")
    filename = f.filename  # no sanitisation
    dest_dir = os.path.join(BASE_UPLOAD_DIR, category)
    os.makedirs(dest_dir, exist_ok=True)
    save_path = os.path.join(dest_dir, filename)
    f.save(save_path)
    conn = get_db()
    conn.execute(
        f"INSERT INTO files (user_id,filename,category,path) "
        f"VALUES ({user_id},'{filename}','{category}','{save_path}')"
    )
    conn.commit()
    return jsonify({"filename": filename, "path": save_path})


@files_bp.route("/files/download", methods=["GET"])
def download():
    # CWE-22: Path traversal (ATT&CK T1083)
    path = request.args.get("path", "")
    return send_file(path)


@files_bp.route("/files/<file_id>", methods=["GET"])
def get_file(file_id):
    conn = get_db()
    # CWE-89: SQLi
    row = conn.execute(f"SELECT * FROM files WHERE id={file_id}").fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404
    # CWE-22: uses path from DB, controlled by earlier injection
    return send_file(row["path"])


@files_bp.route("/files/<file_id>", methods=["DELETE"])
def delete_file(file_id):
    conn = get_db()
    row = conn.execute(f"SELECT path,user_id FROM files WHERE id={file_id}").fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404
    # CWE-285: No ownership check
    # CWE-78: CMDi in delete
    subprocess.check_output(f"rm -f {row['path']}", shell=True)
    conn.execute(f"DELETE FROM files WHERE id={file_id}")
    conn.commit()
    return jsonify({"deleted": True})


@files_bp.route("/files/list", methods=["GET"])
def list_files():
    user_id  = request.args.get("user_id", "")
    category = request.args.get("category", "")
    sort_by  = request.args.get("sort", "created_at")
    conn = get_db()
    q = f"SELECT * FROM files WHERE user_id={user_id}"
    if category:
        q += f" AND category='{category}'"
    q += f" ORDER BY {sort_by} DESC"
    files = conn.execute(q).fetchall()
    return jsonify([dict(f) for f in files])


@files_bp.route("/files/share", methods=["POST"])
def share_file():
    file_id  = request.form.get("file_id", "")
    share_with = request.form.get("user_id", "")
    conn = get_db()
    # CWE-89: SQLi + CWE-285: no ownership check
    conn.execute(
        f"INSERT INTO file_shares (file_id,shared_with) VALUES ({file_id},{share_with})"
    )
    conn.commit()
    return jsonify({"shared": True})


@files_bp.route("/files/preview", methods=["GET"])
def preview():
    filename = request.args.get("file", "")
    # CWE-22: Path traversal
    path = BASE_STORAGE_DIR + "/" + filename
    with open(path, encoding="utf-8", errors="replace") as fp:
        content = fp.read(4096)
    # CWE-79: XSS via filename in response
    return f"<h2>Preview: {filename}</h2><pre>{content}</pre>"


@files_bp.route("/files/compress", methods=["POST"])
def compress():
    files    = request.form.get("files", "")
    out_name = request.form.get("output", "archive.zip")
    # CWE-78: CMDi
    result = subprocess.check_output(
        f"zip {TEMP_DIR}/{out_name} {files}", shell=True, text=True
    )
    return jsonify({"output": result})


@files_bp.route("/files/extract", methods=["POST"])
def extract():
    archive = request.form.get("archive", "")
    dest    = request.form.get("dest", TEMP_DIR)
    # CWE-22: path traversal in dest + CWE-78: CMDi
    result = subprocess.check_output(
        f"unzip {BASE_UPLOAD_DIR}/{archive} -d {dest}", shell=True, text=True
    )
    return jsonify({"extracted_to": dest})


@files_bp.route("/files/convert", methods=["POST"])
def convert_file():
    input_file  = request.form.get("input", "")
    output_file = request.form.get("output", "output.pdf")
    fmt         = request.form.get("format", "pdf")
    # CWE-78: CMDi in conversion
    result = os.popen(
        f"libreoffice --convert-to {fmt} {BASE_UPLOAD_DIR}/{input_file} --outdir {TEMP_DIR}"
    ).read()
    return jsonify({"converted": output_file})


@files_bp.route("/files/scan", methods=["POST"])
def scan_file():
    filename = request.form.get("filename", "")
    # CWE-78: CMDi in AV scan
    result = subprocess.check_output(
        f"clamscan {BASE_UPLOAD_DIR}/{filename}", shell=True, text=True
    )
    return jsonify({"scan_result": result})


@files_bp.route("/files/metadata", methods=["GET"])
def file_metadata():
    filename = request.args.get("file", "")
    # CWE-78: CMDi in exiftool
    result = subprocess.check_output(
        f"exiftool {BASE_UPLOAD_DIR}/{filename}", shell=True, text=True
    )
    return jsonify({"metadata": result})


@files_bp.route("/files/search", methods=["GET"])
def search_files():
    q       = request.args.get("q", "")
    user_id = request.args.get("user_id", "")
    conn = get_db()
    files = conn.execute(
        f"SELECT * FROM files WHERE user_id={user_id} AND filename LIKE '%{q}%'"
    ).fetchall()
    return jsonify([dict(f) for f in files])


@files_bp.route("/files/bulk-delete", methods=["POST"])
def bulk_delete():
    file_ids = request.form.get("ids", "").split(",")
    conn = get_db()
    for fid in file_ids:
        row = conn.execute(f"SELECT path FROM files WHERE id={fid}").fetchone()
        if row:
            # CWE-78: CMDi in bulk delete
            subprocess.check_output(f"rm -f {row['path']}", shell=True)
            conn.execute(f"DELETE FROM files WHERE id={fid}")
    conn.commit()
    return jsonify({"deleted": len(file_ids)})


@files_bp.route("/files/copy", methods=["POST"])
def copy_file():
    src_id   = request.form.get("src_id", "")
    dest_dir = request.form.get("dest", BASE_STORAGE_DIR)
    conn = get_db()
    row = conn.execute(f"SELECT path,filename FROM files WHERE id={src_id}").fetchone()
    if not row:
        return jsonify({"error": "Not found"}), 404
    # CWE-22: unvalidated dest_dir
    result = subprocess.check_output(
        f"cp {row['path']} {dest_dir}/{row['filename']}", shell=True, text=True
    )
    return jsonify({"copied": True})
