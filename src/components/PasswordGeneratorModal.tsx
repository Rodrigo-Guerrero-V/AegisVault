import { useEffect, useState } from "react";
import { Check, Copy, RefreshCw, ShieldCheck, X } from "lucide-react";
import { vaultCommands } from "../ipc/commands";
import { parseVaultError, type PasswordGenOptions } from "../ipc/types";

interface Props {
  open: boolean;
  onClose: () => void;
  onSelectPassword?: (value: string) => void;
}

export function PasswordGeneratorModal({ open, onClose, onSelectPassword }: Props) {
  const [opts, setOpts] = useState<PasswordGenOptions>({
    length: 24,
    uppercase: true,
    lowercase: true,
    digits: true,
    symbols: true,
    exclude_ambiguous: true,
  });
  const [generated, setGenerated] = useState("");
  const [entropy, setEntropy] = useState(0);
  const [copiedLocal, setCopiedLocal] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const regenerate = async (nextOpts: PasswordGenOptions = opts) => {
    setError(null);
    try {
      const res = await vaultCommands.generatePassword(nextOpts);
      setGenerated(res.value);
      setEntropy(res.entropy_bits);
      setCopiedLocal(false);
    } catch (err) {
      setError(parseVaultError(err).message);
    }
  };

  useEffect(() => {
    if (open) {
      void regenerate(opts);
    }
  }, [open]);

  if (!open) return null;

  const updateOpt = <K extends keyof PasswordGenOptions>(
    key: K,
    val: PasswordGenOptions[K]
  ) => {
    const next = { ...opts, [key]: val };
    setOpts(next);
    void regenerate(next);
  };

  const strengthLabel =
    entropy >= 110 ? "Excelente (Resistente a fuerza bruta)" : entropy >= 75 ? "Fuerte" : "Moderada";

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal-panel" onClick={(e) => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <ShieldCheck size={20} color="var(--accent)" />
            <h3 style={{ margin: 0 }}>Generador Criptográfico (CSPRNG)</h3>
          </div>
          <button className="btn btn-secondary" onClick={onClose} aria-label="Cerrar">
            <X size={16} />
          </button>
        </div>

        {error && <div className="alert-box alert-error">{error}</div>}

        <div className="secret-field-card" style={{ flexDirection: "column", alignItems: "stretch" }}>
          <div
            className="mono"
            style={{
              fontSize: 16,
              wordBreak: "break-all",
              lineHeight: 1.5,
              color: "var(--accent)",
              userSelect: "text",
            }}
          >
            {generated}
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 8 }}>
            <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>
              {strengthLabel} · <strong>{entropy} bits</strong>
            </span>
            <div style={{ display: "flex", gap: 6 }}>
              <button className="btn btn-secondary" onClick={() => void regenerate(opts)} title="Regenerar">
                <RefreshCw size={15} />
              </button>
              {!onSelectPassword && (
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={async () => {
                    try {
                      await vaultCommands.copyTextProtected(generated, "generated_password");
                      setCopiedLocal(true);
                    } catch (err) {
                      setError(parseVaultError(err).message);
                    }
                  }}
                >
                  {copiedLocal ? <Check size={15} /> : <Copy size={15} />}
                  {copiedLocal ? "Copiada (segura)" : "Copiar"}
                </button>
              )}
            </div>
          </div>
        </div>

        <div className="field-group">
          <label className="field-label">
            Longitud: <strong>{opts.length} caracteres</strong>
          </label>
          <input
            type="range"
            min={8}
            max={64}
            value={opts.length}
            onChange={(e) => updateOpt("length", Number(e.target.value))}
          />
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 18 }}>
          {(
            [
              ["uppercase", "Mayúsculas (A-Z)"],
              ["lowercase", "Minúsculas (a-z)"],
              ["digits", "Dígitos (0-9)"],
              ["symbols", "Símbolos (!@#$)"],
              ["exclude_ambiguous", "Excluir ambiguos (0O1lI|)"],
            ] as const
          ).map(([key, label]) => (
            <label
              key={key}
              style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, cursor: "pointer" }}
            >
              <input
                type="checkbox"
                checked={opts[key]}
                onChange={(e) => updateOpt(key, e.target.checked)}
              />
              {label}
            </label>
          ))}
        </div>

        {onSelectPassword && (
          <button
            className="btn btn-primary"
            style={{ width: "100%" }}
            onClick={() => {
              onSelectPassword(generated);
              onClose();
            }}
          >
            Usar esta contraseña
          </button>
        )}
      </div>
    </div>
  );
}
