"""
Deliberately vulnerable local target for smoke-testing the scanner.
Not for anything but this test.
"""
from flask import Flask, request
import sqlite3

app = Flask(__name__)

conn = sqlite3.connect(":memory:", check_same_thread=False)
conn.execute("CREATE TABLE products (id INTEGER, name TEXT)")
conn.execute("INSERT INTO products VALUES (1, 'Widget')")
conn.commit()


@app.route("/")
def home():
    return "<html><body><a href='/search?q=test'>search</a> <a href='/products?id=1'>products</a> <a href='/file?path=readme.txt'>file</a></body></html>"


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<html><body>Results for: {q}</body></html>"  # deliberately unescaped


@app.route("/products")
def products():
    pid = request.args.get("id", "1")
    query = f"SELECT * FROM products WHERE id = '{pid}'"  # deliberately concatenated
    try:
        cur = conn.execute(query)
        rows = cur.fetchall()
    except sqlite3.Error:
        rows = []
    return f"<html><body>Rows: {rows}</body></html>"


@app.route("/file")
def file_read():
    path = request.args.get("path", "")
    if ".." in path:
        try:
            with open("/etc/passwd") as f:
                return f"<pre>{f.read()}</pre>"
        except Exception:
            return "no"
    return f"<pre>contents of {path}</pre>"


if __name__ == "__main__":
    app.run(port=9090)
