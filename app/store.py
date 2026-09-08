from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.database import db, rows_to_dicts


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def get_user_by_username(username: str) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None


def get_user(user_id: int) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def get_patient_for_user(user_id: int) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM patients WHERE user_id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def get_patient(patient_id: int) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM patients WHERE id = ?", (patient_id,)).fetchone()
        return dict(row) if row else None


def list_patients() -> list[dict[str, Any]]:
    with db() as conn:
        return rows_to_dicts(conn.execute("SELECT * FROM patients ORDER BY full_name").fetchall())


def get_policy_for_patient(patient_id: int) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM policies WHERE patient_id = ? ORDER BY id DESC LIMIT 1",
            (patient_id,),
        ).fetchone()
        return dict(row) if row else None


def insert_claim(values: dict[str, Any]) -> int:
    cols = ", ".join(values)
    placeholders = ", ".join("?" for _ in values)
    with db() as conn:
        cur = conn.execute(f"INSERT INTO claims ({cols}) VALUES ({placeholders})", tuple(values.values()))
        return int(cur.lastrowid)


def update_claim(claim_id: int, values: dict[str, Any]) -> None:
    assignments = ", ".join(f"{k} = ?" for k in values)
    with db() as conn:
        conn.execute(f"UPDATE claims SET {assignments} WHERE id = ?", (*values.values(), claim_id))


def insert_document(values: dict[str, Any]) -> None:
    cols = ", ".join(values)
    placeholders = ", ".join("?" for _ in values)
    with db() as conn:
        conn.execute(f"INSERT INTO documents ({cols}) VALUES ({placeholders})", tuple(values.values()))


def replace_factors(claim_id: int, factors: list[dict[str, Any]]) -> None:
    with db() as conn:
        conn.execute("DELETE FROM decision_factors WHERE claim_id = ?", (claim_id,))
        for f in factors:
            conn.execute(
                """INSERT INTO decision_factors (claim_id, name, category, severity, score_delta, passed, detail)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (claim_id, f["name"], f["category"], f["severity"], f["score_delta"], int(f["passed"]), f["detail"]),
            )


def get_claim(claim_id: int) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute(
            """SELECT c.*, p.full_name, p.date_of_birth, p.member_id, p.zip_code,
                      pol.policy_number, pol.status AS policy_status, pol.annual_limit,
                      pol.used_to_date, pol.deductible, pol.network, pol.effective_from, pol.effective_to
               FROM claims c
               JOIN patients p ON p.id = c.patient_id
               LEFT JOIN policies pol ON pol.id = c.policy_id
               WHERE c.id = ?""",
            (claim_id,),
        ).fetchone()
        return dict(row) if row else None


def list_claims(role: str, user_id: int, patient_id: int | None = None) -> list[dict[str, Any]]:
    sql = """SELECT c.*, p.full_name, p.member_id
             FROM claims c JOIN patients p ON p.id = c.patient_id"""
    args: list[Any] = []
    if role == "patient" and patient_id:
        sql += " WHERE c.patient_id = ?"
        args.append(patient_id)
    sql += " ORDER BY c.created_at DESC"
    with db() as conn:
        return rows_to_dicts(conn.execute(sql, args).fetchall())


def list_documents(claim_id: int) -> list[dict[str, Any]]:
    with db() as conn:
        return rows_to_dicts(
            conn.execute("SELECT * FROM documents WHERE claim_id = ? ORDER BY id", (claim_id,)).fetchall()
        )


def get_document(doc_id: int) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
        return dict(row) if row else None


def list_factors(claim_id: int) -> list[dict[str, Any]]:
    with db() as conn:
        return rows_to_dicts(
            conn.execute("SELECT * FROM decision_factors WHERE claim_id = ? ORDER BY id", (claim_id,)).fetchall()
        )


def prior_claims(patient_id: int) -> list[dict[str, Any]]:
    with db() as conn:
        return rows_to_dicts(
            conn.execute("SELECT * FROM claims WHERE patient_id = ? ORDER BY created_at DESC", (patient_id,)).fetchall()
        )


def dashboard_stats(role: str, patient_id: int | None) -> dict[str, Any]:
    where = "WHERE patient_id = ?" if role == "patient" and patient_id else ""
    args = (patient_id,) if where else ()
    with db() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM claims {where}", args).fetchone()[0]
        by_status = rows_to_dicts(
            conn.execute(f"SELECT status, COUNT(*) AS n FROM claims {where} GROUP BY status", args).fetchall()
        )
        avg_fraud = conn.execute(f"SELECT AVG(fraud_probability) FROM claims {where}", args).fetchone()[0] or 0
        high_risk = conn.execute(
            f"SELECT COUNT(*) FROM claims {where} {'AND' if where else 'WHERE'} fraud_probability >= 0.55",
            args,
        ).fetchone()[0]
        pending = conn.execute(
            f"SELECT COUNT(*) FROM claims {where} {'AND' if where else 'WHERE'} status IN ('SUBMITTED', 'MANUAL_REVIEW', 'REQUEST_INFO')",
            args,
        ).fetchone()[0]
    status_map = {r["status"]: r["n"] for r in by_status}
    return {
        "total": total,
        "pending": pending,
        "approved": status_map.get("APPROVED", 0),
        "denied": status_map.get("DENIED", 0),
        "high_risk": high_risk,
        "avg_fraud": round(float(avg_fraud) * 100, 1),
        "by_status": status_map,
    }


def list_audit(limit: int = 80) -> list[dict[str, Any]]:
    with db() as conn:
        return rows_to_dicts(
            conn.execute(
                """SELECT a.*, u.username, u.display_name
                   FROM audit_log a LEFT JOIN users u ON u.id = a.user_id
                   ORDER BY a.id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        )


def write_audit(user_id: int | None, action: str, entity: str, entity_id: str | None, detail: str, ip: str | None) -> None:
    with db() as conn:
        conn.execute(
            """INSERT INTO audit_log (user_id, action, entity, entity_id, detail, ip, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (user_id, action, entity, entity_id, detail, ip, now()),
        )
