from flask import Flask, request, jsonify, render_template
import re
import dns.resolver
import smtplib
import csv

app = Flask(__name__)

# Email validation functions
def validate_email_syntax(email):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, email) is not None

def get_mx_records(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return [str(mx.exchange) for mx in mx_records]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        return []
    except Exception as e:
        print(f"Error while checking MX records for {domain}: {e}")
        return []

def validate_email_domain(email):
    domain = email.split('@')[-1]
    mx_records = get_mx_records(domain)
    return len(mx_records) > 0, mx_records

def validate_email_smtp(email, mx_records):
    if not mx_records:
        return False

    try:
        mail_server = mx_records[0]
        with smtplib.SMTP(mail_server) as server:
            server.set_debuglevel(0)
            server.helo()
            server.mail('marisudhir2000@gmail.com')
            code, _ = server.rcpt(email)
            return code == 250
    except Exception as e:
        print(f"SMTP error for {email}: {e}")
        return False

def is_valid_email(email):
    if not validate_email_syntax(email):
        return "Invalid syntax"

    domain_valid, mx_records = validate_email_domain(email)
    if not domain_valid:
        return "Invalid domain"

    smtp_valid = validate_email_smtp(email, mx_records)
    if not smtp_valid:
        return "Undeliverable"

    return "Valid"

# Define a basic list of known spam domains
SPAM_DOMAINS = {'spamdomain.com', 'fakeemail.com'}

def is_spam_email(email):
    domain = email.split('@')[-1]
    return domain in SPAM_DOMAINS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/validate', methods=['POST'])
def validate():
    email = request.form.get('email')
    if not email:
        return jsonify({'error': 'No email provided'}), 400

    syntax_valid = validate_email_syntax(email)
    domain_valid, mx_records = validate_email_domain(email) if syntax_valid else (False, [])
    smtp_valid = validate_email_smtp(email, mx_records) if domain_valid and mx_records else False
    spam_status = is_spam_email(email)

    result = {
        'email': email,
        'syntax_valid': syntax_valid,
        'domain_valid': domain_valid,
        'mx_records': mx_records,
        'smtp_valid': smtp_valid,
        'is_spam': spam_status
    }

    return jsonify(result)

@app.route('/bulk-validate', methods=['POST'])
def bulk_validate():
    file = request.files.get('file')
    if not file:
        return jsonify({'error': 'No file uploaded'}), 400

    # Read file content as text using the file stream directly
    file_content = file.read().decode('utf-8').splitlines()

    # Use csv.reader to process the CSV content
    csv_reader = csv.DictReader(file_content)
    results = []

    for row in csv_reader:
        email = row.get('email', '')
        if not validate_email_syntax(email):
            result = {
                'email': email,
                'syntax_valid': False,
                'domain_valid': False,
                'mx_records': [],
                'smtp_valid': False,
                'is_spam': is_spam_email(email),
                'result': 'Invalid syntax'
            }
        else:
            domain_valid, mx_records = validate_email_domain(email)
            smtp_valid = validate_email_smtp(email, mx_records) if domain_valid else False
            result = {
                'email': email,
                'syntax_valid': True,
                'domain_valid': domain_valid,
                'mx_records': mx_records,
                'smtp_valid': smtp_valid,
                'is_spam': is_spam_email(email),
                'result': 'Valid' if smtp_valid else 'Undeliverable'
            }
        results.append(result)

    return jsonify(results)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
