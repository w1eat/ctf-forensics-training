"""Print synthetic audit events with explicit UTC+8 offset."""
import argparse, datetime as dt, json
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__); p.add_argument('input'); a=p.parse_args()
for number,line in enumerate(Path(a.input).read_text(encoding='utf-8').splitlines(),1):
    row=json.loads(line); original=dt.datetime.fromisoformat(row['timestamp'].replace('Z','+00:00'))
    local=original.astimezone(dt.timezone(dt.timedelta(hours=8)))
    print(number,local.isoformat(),row['event'],row['request_id'],row['user'],row['client_ip'])
