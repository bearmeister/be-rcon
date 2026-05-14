# be-rcon

**v2.12.5**

Unofficial Python client for the [BattlEye RCon
protocol](https://www.battleye.com/downloads/BERConProtocol.txt) over
UDP. Pure standard library, zero runtime dependencies. Built for DayZ
and Arma server administration.

> **Disclaimer.** Not affiliated with or endorsed by BattlEye
> Innovations e.K. "BattlEye" is a trademark of BattlEye Innovations
> e.K. This project implements the publicly published BERConProtocol
> specification under nominative use.

## Install

```bash
pip install git+https://github.com/bearmeister/be-rcon@v2.12.5
```

(No PyPI release yet: pin to a tag.) Requires Python 3.10+.

Or from source:

```bash
git clone https://github.com/bearmeister/be-rcon
cd be-rcon
pip install -e .
```

## CLI

After install, a `be-rcon` command is on `PATH`.

### One-shot command

```bash
$ be-rcon cmd 10.0.0.5 2305 'rconpassword' players
Players on server:
[#] [IP Address]:[Port] [Ping] [GUID] [Name]
--------------------------------------------------
0   10.20.30.40:2304    52   abc...  Bushy
(1 players in total)
```

### Interactive shell

```bash
$ be-rcon shell 10.0.0.5 2305 'rconpassword'
Connected to 10.0.0.5:2305. Type 'exit' or Ctrl-D to quit.
rcon> players
Players on server:
[#] [IP Address]:[Port] [Ping] [GUID] [Name]
--------------------------------------------------
0   10.20.30.40:2304    52   abc...  Bushy
(1 players in total)
rcon> say -1 Server restarting in 5 minutes
rcon> #shutdown 300
rcon> exit
$
```

Line editing and command history are provided by `readline`. Type
`exit`, `quit`, or Ctrl-D to leave the shell.

> **Security note.** Passing the RCon password as a positional CLI
> argument leaves it in shell history and `ps` output. For long-lived
> automation, prefer the library API and source the password from an
> environment variable or secret store.

## Library use

```python
from be_rcon import RConClient

with RConClient("server.example.com", 2305, "rconpassword") as rc:
    print(rc.send_command("players"))
```

### Listening for broadcasts

```python
from be_rcon import RConClient

def on_msg(line: str) -> None:
    print("server:", line)

with RConClient("server.example.com", 2305, "rconpassword") as rc:
    rc.listen(on_msg)   # blocks; ACKs broadcasts, sends keepalives
```

`RConClient` is not thread-safe. Instantiate one per thread.

## API

| Symbol | Purpose |
|--------|---------|
| `RConClient(host, port, password, timeout=5.0)` | Connection + context manager |
| `RConClient.send_command(str) -> str` | Single command, reassembled multi-packet response |
| `RConClient.listen(callback)` | Broadcast loop with auto-ACK + keepalive |
| `cli_cmd(args)` | One-shot CLI: positional args `host port password command...` |
| `cli_shell(args)` | Interactive REPL |
| `main(argv=None)` | Console-script entry point: dispatches `cmd` / `shell` |

## Protocol notes

- Transport: UDP, IPv4. Packet framing: `'BE' | CRC32-LE | 0xFF | type | payload`.
- CRC32 covers everything from the `0xFF` marker onward.
- Multi-part responses are reassembled by sequence number.
- Broadcasts are ACK'd automatically inside `listen()`.
- Latin-1 encoding throughout: BattlEye predates Unicode and DayZ
  servers commonly emit cp1252 player names.

## Status

Battle-tested in production on a live DayZ server.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
