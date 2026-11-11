import { useState } from "react";
import { Eye, EyeOff, History } from "lucide-react";
import type { PasswordHistoryEntry } from "../ipc/types";

interface Props {
  entries: PasswordHistoryEntry[];
}

export function PasswordHistoryPopover({ entries }: Props) {
  const [open, setOpen] = useState(false);
  const [revealedIdx, setRevealedIdx] = useState<number | null>(null);

  if (!entries || entries.length === 0) return null;

  return (
    <div style={{ marginTop: 12 }}>
      <button
        type="button"
        className="btn btn-secondary"
        onClick={() => setOpen((v) => !v)}
      >
        <History size={15} />
        Historial de contraseñas ({entries.length})
      </button>

      {open && (
        <div
          style={{
            marginTop: 10,
            background: "var(--bg-input)",
            border: "1px solid var(--border-subtle)",
            borderRadius: 10,
            padding: 12,
          }}
        >
          {entries.map((entry, idx) => {
            const visible = revealedIdx === idx;
            const dateStr = new Date(entry.changed_at * 1000).toLocaleString("es-CL");
            return (
              <div
                key={`${entry.changed_at}-${idx}`}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "8px 0",
                  borderBottom: idx + 1 < entries.length ? "1px solid var(--border-subtle)" : "none",
                }}
              >
                <div>
                  <div className="mono" style={{ fontSize: 13 }}>
                    {visible ? entry.password : "••••••••••••••••"}
                  </div>
                  <div style={{ fontSize: 11, color: "var(--text-muted)" }}>
                    Reemplazada el {dateStr}
                  </div>
                </div>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setRevealedIdx(visible ? null : idx)}
                >
                  {visible ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
