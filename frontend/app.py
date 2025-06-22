import os
import zipfile
import tempfile
from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from werkzeug.utils import secure_filename
from secret_scanner import SecretScanner
from dependency_scanner import DependencyScanner
from ai_vuln_scanner import AIVulnScanner
from pdf_report import generate_pdf_report

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

scanners = [SecretScanner(), DependencyScanner(), AIVulnScanner()]

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    uploaded_file = request.files['file']
    if uploaded_file.filename.endswith('.zip'):
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, secure_filename(uploaded_file.filename))
        uploaded_file.save(zip_path)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        scan_path = temp_dir
    else:
        scan_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(uploaded_file.filename))
        uploaded_file.save(scan_path)
    request.environ['scan_path'] = scan_path
    return redirect(url_for('scan'))

@app.route('/scan', methods=['GET'])
def scan():
    scan_path = request.environ.get('scan_path')
    if not scan_path:
        return redirect(url_for('index'))
    findings = []
    file_count = 0
    for root, _, files in os.walk(scan_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_count += 1
            for scanner in scanners:
                try:
                    findings.extend(scanner.scan_file(file_path))
                except Exception:
                    pass
    return render_template('scan_results.html', findings=findings, file_count=file_count)

@app.route('/download_report', methods=['POST'])
def download_report():
    findings = request.json.get('findings', [])
    project_name = request.json.get('project_name', 'Project')
    file_count = request.json.get('file_count', 0)
    output_path = os.path.join(tempfile.gettempdir(), 'scan_report.pdf')
    generate_pdf_report(findings, output_path, project_name, file_count, findings)
    return send_file(output_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True) 