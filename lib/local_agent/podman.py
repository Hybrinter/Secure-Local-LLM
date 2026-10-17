"""Shared podman helpers: subnet collision checks and label inspection."""

from __future__ import annotations

import ipaddress
import json

from .runner import RunnerError


class PodmanError(Exception):
    pass


def must(runner, args, label, timeout=60):
    try:
        res = runner.podman(args, timeout=timeout)
    except RunnerError as exc:
        raise PodmanError(f"{label}: {exc}") from exc
    if res.timed_out:
        raise PodmanError(f"{label}: timed out")
    if res.returncode != 0:
        raise PodmanError(
            f"{label}: rc={res.returncode} {res.stderr.strip()[-300:]}"
        )
    return res.stdout


def _inspect_labels(runner, kind, ident):
    field = ".Config.Labels" if kind in ("container", "image") else ".Labels"
    res = runner.podman(
        [kind, "inspect", ident, "--format", f"{{{{json {field}}}}}"],
        timeout=30,
    )
    if res.returncode != 0 or res.timed_out:
        return None
    try:
        labels = json.loads(res.stdout)
    except json.JSONDecodeError:
        return None
    return labels if isinstance(labels, dict) else {}


def object_labels(runner, kind, ident):
    if kind == "network":
        out = must(
            runner, ["network", "inspect", ident], f"inspect network {ident}"
        )
        try:
            info = json.loads(out)
        except json.JSONDecodeError as exc:
            raise PodmanError(f"unparsable network inspect for {ident}") from exc
        if not isinstance(info, list) or not info or not isinstance(
            info[0], dict
        ):
            raise PodmanError(f"unexpected network inspect for {ident}")
        labels = info[0].get("labels")
        return labels if isinstance(labels, dict) else {}
    return _inspect_labels(runner, kind, ident)


def _network_info(runner, name):
    out = must(runner, ["network", "inspect", name],
               f"inspect network {name}")
    try:
        info = json.loads(out)
        if not isinstance(info, list) or not info or not isinstance(
            info[0], dict
        ):
            raise ValueError("empty")
        return info[0]
    except (json.JSONDecodeError, ValueError) as exc:
        raise PodmanError(
            f"unparsable network inspect for {name}") from exc


def network_subnet(runner, name):
    try:
        return ipaddress.ip_network(
            _network_info(runner, name)["subnets"][0]["subnet"])
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise PodmanError(
            f"unparsable subnet data for network {name}") from exc


def network_id(runner, name):
    try:
        ident = _network_info(runner, name)["id"]
    except (KeyError, TypeError) as exc:
        raise PodmanError(f"no id for network {name}") from exc
    if not isinstance(ident, str) or len(ident) != 64 or not all(
        c in "0123456789abcdef" for c in ident
    ):
        raise PodmanError(f"network {name} id is not hex64")
    return ident


def object_exists(runner, kind, ident):
    if kind == "volume":
        res = runner.podman(
            ["volume", "inspect", ident], timeout=30
        )
    elif kind == "pod":
        res = runner.podman(["pod", "inspect", ident], timeout=30)
    elif kind == "network":
        res = runner.podman(["network", "inspect", ident], timeout=30)
    else:
        res = runner.podman(["inspect", ident], timeout=30)
    return res.returncode == 0 and not res.timed_out


def podman_subnets(runner):
    out = must(runner, ["network", "ls", "--format", "{{.Name}}"],
               "network ls")
    used = []
    for name in out.split():
        raw = must(
            runner,
            ["network", "inspect", name, "--format", "{{json .Subnets}}"],
            f"inspect network {name}",
        )
        try:
            subs = json.loads(raw) or []
        except json.JSONDecodeError as exc:
            raise PodmanError(
                f"unparsable subnet data for network {name}"
            ) from exc
        for sub in subs:
            try:
                used.append(ipaddress.ip_network(sub["subnet"]))
            except (KeyError, ValueError, TypeError) as exc:
                raise PodmanError(
                    f"unparsable subnet data for network {name}"
                ) from exc
    return used


def _route_nets(text):
    nets = []
    for line in text.splitlines():
        parts = line.split()
        if not parts:
            continue
        dst = parts[0]
        if dst in ("default", "nexthop"):
            continue
        try:
            nets.append(ipaddress.ip_network(dst, strict=False))
        except ValueError as exc:
            raise PodmanError(f"unparsable route entry: {line!r}") from exc
    return nets


def used_subnets(runner):
    used = podman_subnets(runner)
    res = runner.run(["ip", "-4", "-o", "route", "show"], timeout=15)
    if res.returncode != 0 or res.timed_out:
        raise PodmanError("host route list failed")
    used.extend(_route_nets(res.stdout))
    res = runner.podman(
        ["unshare", "--rootless-netns", "ip", "-4", "-o", "route", "show"],
        timeout=30,
    )
    if res.returncode != 0 or res.timed_out:
        raise PodmanError("rootless route list failed")
    used.extend(_route_nets(res.stdout))
    return used


def free_subnet4(runner):
    used = used_subnets(runner)
    for third in range(256):
        for last in range(0, 256, 16):
            cand = ipaddress.ip_network(f"10.240.{third}.{last}/28")
            if not any(cand.overlaps(u) for u in used):
                return cand
    raise PodmanError("no free IPv4 /28 subnet available")
