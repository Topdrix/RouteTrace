# RouteTrace

RouteTrace is a Flask app with a manually implemented IPv4 traceroute. It sends
UDP probes and receives ICMP responses through Python sockets; it does not call
the operating system's `traceroute` or `tracert` command.

## Run the web app

1. Install the packages with `python -m pip install -r requirements.txt`.
2. Make sure PostgreSQL is running and the database connection settings near
   the top of `app.py` match your local database.
3. Start the app with `python app.py`, then open `http://127.0.0.1:5000`.
4. Register an account, log in, and enter a host name or IPv4 address on the
   dashboard.

## Run a trace from the terminal

From the project directory, run:

```text
python route_trace.py example.com
```

The optional `--max-hops` and `--timeout` arguments let you customize the
trace, for example `python route_trace.py example.com --max-hops 12 --timeout 1`.
The terminal command uses the same Python socket implementation as the
dashboard and does not require the Flask server or PostgreSQL to be running.

On Windows, raw ICMP sockets generally require an elevated terminal. If socket
creation is denied, reopen PowerShell as Administrator and retry. Asterisks in
the results mean that no ICMP response arrived before that hop's timeout.
