"""Read-only query of the course's synthetic SQLite database."""
import argparse, sqlite3
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__); p.add_argument('input'); a=p.parse_args()
uri=Path(a.input).resolve().as_uri()+'?mode=ro'; con=sqlite3.connect(uri,uri=True)
print('Tables:',list(con.execute("SELECT name FROM sqlite_master WHERE type='table'")))
print('Columns:',list(con.execute('PRAGMA table_info(artifacts)')))
for row in con.execute('SELECT id,name,note FROM artifacts WHERE deleted=1'): print(row)
con.close()
