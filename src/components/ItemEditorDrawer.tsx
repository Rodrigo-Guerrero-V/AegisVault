import { useEffect, useState } from "react";
import { KeyRound, Save, WandSparkles, X } from "lucide-react";
import { vaultCommands } from "../ipc/commands";
import {
  parseVaultError,
  type CachedItemOverview,
  type FolderDto,
  type ItemDetailDto,
  type ItemType,
  type SaveItemInput,
} from "../ipc/types";
import { PasswordGeneratorModal } from "./PasswordGeneratorModal";

interface Props {
  open: boolean;
  editingItem: ItemDetailDto | null;
  folders: FolderDto[];
  defaultType?: ItemType;
  onClose: () => void;
  onSaved: (overview: CachedItemOverview) => void;
}

export function ItemEditorDrawer({
  open,
  editingItem,
  folders,
  defaultType = "login",
  onClose,
  onSaved,
}: Props) {
  const [itemType, setItemType] = useState<ItemType>(defaultType);
  const [title, setTitle] = useState("");
  const [folderId, setFolderId] = useState<string>("");
  const [favorite, setFavorite] = useState(false);
  const [tagsText, setTagsText] = useState("");

  // Campos Login
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [urlText, setUrlText] = useState("");
  const [totpUri, setTotpUri] = useState("");
  const [notes, setNotes] = useState("");

  // Campos Note
  const [noteBody, setNoteBody] = useState("");

  // Campos Card
  const [cardholder, setCardholder] = useState("");
  const [cardNumber, setCardNumber] = useState("");
  const [expMonth, setExpMonth] = useState("12");
  const [expYear, setExpYear] = useState("2029");
  const [cvv, setCvv] = useState("");
  const [cardPin, setCardPin] = useState("");

  const [genOpen, setGenOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setError(null);

    if (editingItem) {
      setItemType(editingItem.item_type);
      setTitle(editingItem.overview.title);
      setFolderId(editingItem.folder_id ?? "");
      setFavorite(editingItem.favorite);
      setTagsText(editingItem.overview.tags.join(", "));
      setUrlText(editingItem.overview.urls.join("\n"));

      if (editingItem.secret.kind === "login") {
        setUsername(editingItem.secret.username);
        setPassword(editingItem.secret.password);
        setTotpUri(editingItem.secret.totp_uri ?? "");
        setNotes(editingItem.secret.notes ?? "");
      } else if (editingItem.secret.kind === "note") {
        setNoteBody(editingItem.secret.body);
      } else if (editingItem.secret.kind === "card") {
        setCardholder(editingItem.secret.cardholder_name);
        setCardNumber(editingItem.secret.card_number);
        setExpMonth(editingItem.secret.exp_month);
        setExpYear(editingItem.secret.exp_year);
        setCvv(editingItem.secret.cvv);
        setCardPin(editingItem.secret.pin ?? "");
        setNotes(editingItem.secret.notes ?? "");
      }
    } else {
      setItemType(defaultType);
      setTitle("");
      setFolderId("");
      setFavorite(false);
      setTagsText("");
      setUsername("");
      setPassword("");
      setUrlText("");
      setTotpUri("");
      setNotes("");
      setNoteBody("");
      setCardholder("");
      setCardNumber("");
      setExpMonth("12");
      setExpYear("2029");
      setCvv("");
      setCardPin("");
    }
  }, [open, editingItem, defaultType]);

  if (!open) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    const urls = urlText
      .split(/\r?\n/)
      .map((u) => u.trim())
      .filter(Boolean);
    const tags = tagsText
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);

    let payload: SaveItemInput;
    if (itemType === "login") {
      payload = {
        id: editingItem?.id ?? null,
        folder_id: folderId || null,
        item_type: "login",
        favorite,
        overview: { title, subtitle: username, urls, tags },
        secret: {
          kind: "login",
          username,
          password,
          totp_uri: totpUri.trim() || null,
          notes: notes.trim() || null,
        },
      };
    } else if (itemType === "note") {
      payload = {
        id: editingItem?.id ?? null,
        folder_id: folderId || null,
        item_type: "note",
        favorite,
        overview: {
          title,
          subtitle: "Nota cifrada",
          urls: [],
          tags,
        },
        secret: {
          kind: "note",
          body: noteBody,
        },
      };
    } else {
      const digits = cardNumber.replace(/\D/g, "");
      const masked = digits.length >= 4 ? `•••• ${digits.slice(-4)}` : cardholder;
      payload = {
        id: editingItem?.id ?? null,
        folder_id: folderId || null,
        item_type: "card",
        favorite,
        overview: {
          title,
          subtitle: masked,
          urls: [],
          tags,
        },
        secret: {
          kind: "card",
          cardholder_name: cardholder,
          card_number: cardNumber,
          exp_month: expMonth,
          exp_year: expYear,
          cvv,
          pin: cardPin.trim() || null,
          notes: notes.trim() || null,
        },
      };
    }

    try {
      const saved = await vaultCommands.saveItem(payload);
      onSaved(saved);
      onClose();
    } catch (err) {
      setError(parseVaultError(err).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <form
        className="modal-panel"
        style={{ maxWidth: 580 }}
        onClick={(e) => e.stopPropagation()}
        onSubmit={handleSubmit}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <KeyRound size={19} color="var(--accent)" />
            <h3 style={{ margin: 0 }}>
              {editingItem ? "Editar registro" : "Nuevo registro en bóveda"}
            </h3>
          </div>
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        {error && <div className="alert-box alert-error">{error}</div>}

        {!editingItem && (
          <div className="field-group">
            <label className="field-label">Tipo de ítem</label>
            <select
              className="select-input"
              value={itemType}
              onChange={(e) => setItemType(e.target.value as ItemType)}
            >
              <option value="login">Credencial de acceso (Login + 2FA)</option>
              <option value="note">Nota segura</option>
              <option value="card">Tarjeta de pago</option>
            </select>
          </div>
        )}

        <div style={{ display: "grid", gridTemplateColumns: "1fr 200px", gap: 12 }}>
          <div className="field-group">
            <label className="field-label">Título *</label>
            <input
              className="text-input"
              required
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Ej. GitHub Personal"
            />
          </div>
          <div className="field-group">
            <label className="field-label">Carpeta</label>
            <select
              className="select-input"
              value={folderId}
              onChange={(e) => setFolderId(e.target.value)}
            >
              <option value="">Sin carpeta</option>
              {folders.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {itemType === "login" && (
          <>
            <div className="field-group">
              <label className="field-label">Usuario o correo</label>
              <input
                className="text-input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="off"
              />
            </div>

            <div className="field-group">
              <label className="field-label">Contraseña</label>
              <div style={{ display: "flex", gap: 8 }}>
                <input
                  className="text-input mono"
                  type="text"
                  required={itemType === "login"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="off"
                />
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setGenOpen(true)}
                  title="Generar con CSPRNG"
                >
                  <WandSparkles size={16} />
                  Generar
                </button>
              </div>
            </div>

            <div className="field-group">
              <label className="field-label">Semilla TOTP 2FA (Base32 o URI otpauth://)</label>
              <input
                className="text-input mono"
                value={totpUri}
                onChange={(e) => setTotpUri(e.target.value)}
                placeholder="JBSWY3DPEHPK3PXP..."
                autoComplete="off"
              />
            </div>

            <div className="field-group">
              <label className="field-label">URLs asociadas (una por línea)</label>
              <textarea
                className="text-area"
                rows={2}
                value={urlText}
                onChange={(e) => setUrlText(e.target.value)}
                placeholder="https://github.com"
              />
            </div>

            <div className="field-group">
              <label className="field-label">Notas privadas</label>
              <textarea
                className="text-area"
                rows={2}
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
              />
            </div>
          </>
        )}

        {itemType === "note" && (
          <div className="field-group">
            <label className="field-label">Contenido cifrado</label>
            <textarea
              className="text-area mono"
              rows={7}
              value={noteBody}
              onChange={(e) => setNoteBody(e.target.value)}
              placeholder="Claves de recuperación, licencias, SSH..."
            />
          </div>
        )}

        {itemType === "card" && (
          <>
            <div className="field-group">
              <label className="field-label">Titular de la tarjeta</label>
              <input
                className="text-input"
                value={cardholder}
                onChange={(e) => setCardholder(e.target.value)}
              />
            </div>
            <div className="field-group">
              <label className="field-label">Número de tarjeta</label>
              <input
                className="text-input mono"
                value={cardNumber}
                onChange={(e) => setCardNumber(e.target.value)}
                autoComplete="off"
              />
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr 1fr", gap: 10 }}>
              <div className="field-group">
                <label className="field-label">Mes</label>
                <input className="text-input" value={expMonth} onChange={(e) => setExpMonth(e.target.value)} />
              </div>
              <div className="field-group">
                <label className="field-label">Año</label>
                <input className="text-input" value={expYear} onChange={(e) => setExpYear(e.target.value)} />
              </div>
              <div className="field-group">
                <label className="field-label">CVV</label>
                <input className="text-input mono" value={cvv} onChange={(e) => setCvv(e.target.value)} />
              </div>
              <div className="field-group">
                <label className="field-label">PIN</label>
                <input className="text-input mono" value={cardPin} onChange={(e) => setCardPin(e.target.value)} />
              </div>
            </div>
          </>
        )}

        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: 10 }}>
          <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 13, cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={favorite}
              onChange={(e) => setFavorite(e.target.checked)}
            />
            Marcar como favorito
          </label>

          <div style={{ display: "flex", gap: 8 }}>
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Cancelar
            </button>
            <button type="submit" className="btn btn-primary" disabled={saving}>
              <Save size={15} />
              {saving ? "Cifrando..." : "Guardar en bóveda"}
            </button>
          </div>
        </div>

        <PasswordGeneratorModal
          open={genOpen}
          onClose={() => setGenOpen(false)}
          onSelectPassword={(val) => setPassword(val)}
        />
      </form>
    </div>
  );
}
