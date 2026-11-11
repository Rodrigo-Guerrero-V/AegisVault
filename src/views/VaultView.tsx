import { useCallback, useEffect, useRef, useState } from "react";
import {
  Copy,
  CreditCard,
  PenLine,
  Eye,
  EyeOff,
  FileText,
  Folder,
  FolderPlus,
  Globe,
  KeyRound,
  Lock,
  Plus,
  Search,
  Settings,
  Shield,
  Star,
  Trash2,
  WandSparkles,
} from "lucide-react";
import { ItemEditorDrawer } from "../components/ItemEditorDrawer";
import { PasswordGeneratorModal } from "../components/PasswordGeneratorModal";
import { PasswordHistoryPopover } from "../components/PasswordHistoryPopover";
import { vaultCommands } from "../ipc/commands";
import {
  parseVaultError,
  type CachedItemOverview,
  type CopyableField,
  type FolderDto,
  type ItemDetailDto,
  type ItemType,
} from "../ipc/types";
import { SettingsSecurityView } from "./SettingsSecurityView";

type SidebarFilter =
  | { kind: "all" }
  | { kind: "favorites" }
  | { kind: "type"; itemType: ItemType }
  | { kind: "folder"; folderId: string }
  | { kind: "settings" };

export function VaultView() {
  const [nav, setNav] = useState<SidebarFilter>({ kind: "all" });
  const [search, setSearch] = useState("");
  const [folders, setFolders] = useState<FolderDto[]>([]);
  const [items, setItems] = useState<CachedItemOverview[]>([]);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<ItemDetailDto | null>(null);
  const [revealSecret, setRevealSecret] = useState(false);

  const [editorOpen, setEditorOpen] = useState(false);
  const [editingTarget, setEditingTarget] = useState<ItemDetailDto | null>(null);
  const [generatorOpen, setGeneratorOpen] = useState(false);
  const [newFolderName, setNewFolderName] = useState("");
  const [addingFolder, setAddingFolder] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadIndex = useCallback(async () => {
    try {
      const dto = await vaultCommands.listVaultIndex({
        search_query: search || null,
        folder_id: nav.kind === "folder" ? nav.folderId : null,
        item_type: nav.kind === "type" ? nav.itemType : null,
      });
      setFolders(dto.folders);
      const filtered =
        nav.kind === "favorites"
          ? dto.items_overview.filter((i) => i.favorite)
          : dto.items_overview;
      setItems(filtered);
    } catch (err) {
      setError(parseVaultError(err).message);
    }
  }, [search, nav]);

  useEffect(() => {
    void loadIndex();
  }, [loadIndex]);

  const totpReloadingRef = useRef(false);

  const loadSelectedDetail = useCallback(async (id: string) => {
    try {
      const full = await vaultCommands.getItemDetail(id);
      setDetail(full);
    } catch (err) {
      setError(parseVaultError(err).message);
    } finally {
      totpReloadingRef.current = false;
    }
  }, []);

  useEffect(() => {
    setRevealSecret(false);
    if (selectedId && nav.kind !== "settings") {
      void loadSelectedDetail(selectedId);
    } else {
      setDetail(null);
    }
  }, [selectedId, nav.kind, loadSelectedDetail]);

  // Reloj reactivo para TOTP (cuenta regresiva local + recarga de código al cruzar ventana de 30s)
  useEffect(() => {
    if (!detail?.current_totp || !selectedId) return;
    const timer = window.setInterval(() => {
      setDetail((prev) => {
        if (!prev || !prev.current_totp) return prev;
        if (prev.current_totp.remaining_secs <= 1) {
          if (!totpReloadingRef.current) {
                totpReloadingRef.current = true;
                void loadSelectedDetail(prev.id);
          }
          return prev;
        }
        return {
          ...prev,
          current_totp: {
            ...prev.current_totp,
            remaining_secs: prev.current_totp.remaining_secs - 1,
          },
        };
      });
    }, 1000);
    return () => window.clearInterval(timer);
  }, [detail?.id, detail?.current_totp !== null, selectedId, loadSelectedDetail]);

  const copySecure = async (field: CopyableField) => {
    if (!detail) return;
    try {
      await vaultCommands.copyItemField(detail.id, field);
    } catch (err) {
      setError(parseVaultError(err).message);
    }
  };

  const handleCreateFolder = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newFolderName.trim()) return;
    try {
      await vaultCommands.saveFolder(newFolderName);
      setNewFolderName("");
      setAddingFolder(false);
      await loadIndex();
    } catch (err) {
      setError(parseVaultError(err).message);
    }
  };

  const iconForType = (t: ItemType) => {
    if (t === "login") return <Globe size={16} color="var(--accent)" />;
    if (t === "card") return <CreditCard size={16} color="#3f5d8a" />;
    return <FileText size={16} color="var(--warn)" />;
  };

  return (
    <div className="workspace-grid">
      {/* Barra lateral izquierda estilo Dashlane */}
      <aside className="sidebar">
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 10px 14px" }}>
          <div className="brand-badge" style={{ width: 32, height: 32 }}>
            <Shield size={18} />
          </div>
          <strong style={{ fontSize: 15 }}>AegisVault</strong>
        </div>

        <button
          className="btn btn-primary"
          style={{ margin: "0 6px 10px" }}
          onClick={() => {
            setEditingTarget(null);
            setEditorOpen(true);
          }}
        >
          <Plus size={16} />
          Añadir ítem
        </button>

        <div className="nav-section-label">Bóveda</div>
        <button
          className={`nav-btn ${nav.kind === "all" ? "active" : ""}`}
          onClick={() => setNav({ kind: "all" })}
        >
          <span>Todos los ítems</span>
        </button>
        <button
          className={`nav-btn ${nav.kind === "favorites" ? "active" : ""}`}
          onClick={() => setNav({ kind: "favorites" })}
        >
          <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Star size={15} /> Favoritos
          </span>
        </button>
        <button
          className={`nav-btn ${nav.kind === "type" && nav.itemType === "login" ? "active" : ""}`}
          onClick={() => setNav({ kind: "type", itemType: "login" })}
        >
          <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <KeyRound size={15} /> Credenciales
          </span>
        </button>
        <button
          className={`nav-btn ${nav.kind === "type" && nav.itemType === "note" ? "active" : ""}`}
          onClick={() => setNav({ kind: "type", itemType: "note" })}
        >
          <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <FileText size={15} /> Notas seguras
          </span>
        </button>
        <button
          className={`nav-btn ${nav.kind === "type" && nav.itemType === "card" ? "active" : ""}`}
          onClick={() => setNav({ kind: "type", itemType: "card" })}
        >
          <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <CreditCard size={15} /> Tarjetas
          </span>
        </button>

        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <span className="nav-section-label">Carpetas</span>
          <button
            className="btn btn-secondary"
            style={{ padding: "3px 6px", fontSize: 11 }}
            onClick={() => setAddingFolder((v) => !v)}
            title="Nueva carpeta"
          >
            <FolderPlus size={13} />
          </button>
        </div>

        {addingFolder && (
          <form onSubmit={handleCreateFolder} style={{ padding: "4px 6px", display: "flex", gap: 4 }}>
            <input
              className="text-input"
              style={{ padding: "6px 8px", fontSize: 12 }}
              placeholder="Nombre..."
              value={newFolderName}
              onChange={(e) => setNewFolderName(e.target.value)}
              autoFocus
            />
          </form>
        )}

        <div style={{ flex: 1, overflowY: "auto" }}>
          {folders.map((f) => (
            <button
              key={f.id}
              className={`nav-btn ${nav.kind === "folder" && nav.folderId === f.id ? "active" : ""}`}
              onClick={() => setNav({ kind: "folder", folderId: f.id })}
            >
              <span style={{ display: "flex", alignItems: "center", gap: 8, overflow: "hidden" }}>
                <Folder size={14} />
                <span style={{ textOverflow: "ellipsis", overflow: "hidden", whiteSpace: "nowrap" }}>
                  {f.name}
                </span>
              </span>
            </button>
          ))}
        </div>

        <div className="nav-section-label">Herramientas</div>
        <button className="nav-btn" onClick={() => setGeneratorOpen(true)}>
          <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <WandSparkles size={15} /> Generador CSPRNG
          </span>
        </button>
        <button
          className={`nav-btn ${nav.kind === "settings" ? "active" : ""}`}
          onClick={() => setNav({ kind: "settings" })}
        >
          <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <Settings size={15} /> Seguridad y Respaldo
          </span>
        </button>
        <button className="nav-btn" onClick={() => void vaultCommands.lockVault()}>
          <span style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--danger)" }}>
            <Lock size={15} /> Bloquear ahora
          </span>
        </button>
      </aside>

      {/* Columna central de búsqueda y listado */}
      {nav.kind === "settings" ? (
        <main className="detail-pane" style={{ gridColumn: "2 / 4" }}>
          <SettingsSecurityView onVaultMutated={() => void loadIndex()} />
        </main>
      ) : (
        <>
          <section className="list-pane">
            <div className="list-toolbar">
              <div style={{ position: "relative", flex: 1 }}>
                <Search
                  size={15}
                  color="var(--text-muted)"
                  style={{ position: "absolute", left: 11, top: 11 }}
                />
                <input
                  className="text-input"
                  style={{ paddingLeft: 34 }}
                  placeholder="Buscar en bóveda..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>
              {nav.kind === "folder" && (
                <button
                  className="btn btn-danger"
                  title="Eliminar carpeta (conserva los ítems)"
                  onClick={async () => {
                    try {
                      await vaultCommands.deleteFolder(nav.folderId);
                      setNav({ kind: "all" });
                    } catch (err) {
                      setError(parseVaultError(err).message);
                    }
                  }}
                >
                  <Trash2 size={15} />
                </button>
              )}
            </div>

            <div className="items-scroll">
              {items.length === 0 ? (
                <div style={{ padding: 28, textAlign: "center", color: "var(--text-muted)", fontSize: 13 }}>
                  No hay registros en esta vista.
                </div>
              ) : (
                items.map((item) => (
                  <button
                    key={item.id}
                    className={`item-row ${selectedId === item.id ? "selected" : ""}`}
                    onClick={() => setSelectedId(item.id)}
                  >
                    <div className="brand-badge" style={{ width: 34, height: 34, flexShrink: 0 }}>
                      {iconForType(item.item_type)}
                    </div>
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div style={{ fontWeight: 600, fontSize: 13.5, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {item.title}
                      </div>
                      <div style={{ fontSize: 12, color: "var(--text-secondary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {item.subtitle || "—"}
                      </div>
                    </div>
                    {item.favorite && <Star size={14} color="var(--warning)" fill="var(--warning)" />}
                  </button>
                ))
              )}
            </div>
          </section>

          {/* Panel derecho de detalle con descifrado puntual */}
          <main className="detail-pane">
            {error && <div className="alert-box alert-error">{error}</div>}

            {!detail ? (
              <div style={{ color: "var(--text-muted)", marginTop: 80, textAlign: "center" }}>
                Selecciona un registro para descifrar sus detalles bajo demanda.
              </div>
            ) : (
              <div style={{ maxWidth: 620 }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 22 }}>
                  <div>
                    <h2 style={{ margin: "0 0 4px" }}>{detail.overview.title}</h2>
                    <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
                      Actualizado el {new Date(detail.updated_at * 1000).toLocaleString("es-CL")}
                    </span>
                  </div>
                  <div style={{ display: "flex", gap: 8 }}>
                    <button
                      className="btn btn-secondary"
                      onClick={() => {
                        setEditingTarget(detail);
                        setEditorOpen(true);
                      }}
                    >
                      <PenLine size={15} />
                      Editar
                    </button>
                    <button
                      className="btn btn-danger"
                      onClick={async () => {
                        try {
                          await vaultCommands.deleteItem(detail.id);
                          setSelectedId(null);
                          await loadIndex();
                        } catch (err) {
                          setError(parseVaultError(err).message);
                        }
                      }}
                    >
                      <Trash2 size={15} />
                    </button>
                  </div>
                </div>

                {detail.secret.kind === "login" && (
                  <>
                    <div className="secret-field-card">
                      <div>
                        <div className="field-label">Usuario</div>
                        <div>{detail.secret.username || "—"}</div>
                      </div>
                      <button className="btn btn-secondary" onClick={() => void copySecure("username")}>
                        <Copy size={14} />
                        Copiar
                      </button>
                    </div>

                    <div className="secret-field-card">
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div className="field-label">Contraseña</div>
                        <div className="mono" style={{ wordBreak: "break-all" }}>
                          {revealSecret ? detail.secret.password : "••••••••••••••••••••"}
                        </div>
                      </div>
                      <div style={{ display: "flex", gap: 6 }}>
                        <button
                          className="btn btn-secondary"
                          onClick={() => setRevealSecret((v) => !v)}
                        >
                          {revealSecret ? <EyeOff size={14} /> : <Eye size={14} />}
                        </button>
                        <button className="btn btn-primary" onClick={() => void copySecure("password")}>
                          <Copy size={14} />
                          Copiar
                        </button>
                      </div>
                    </div>

                    {detail.current_totp && (
                      <div className="secret-field-card">
                        <div>
                          <div className="field-label">
                            Código 2FA (TOTP · expira en {detail.current_totp.remaining_secs}s)
                          </div>
                          <div
                            className="mono"
                            style={{
                              fontSize: 19,
                              color: "var(--accent-strong)",
                              fontWeight: 700,
                              letterSpacing: "0.18em",
                            }}
                          >
                            {detail.current_totp.code.slice(0, 3)} {detail.current_totp.code.slice(3)}
                          </div>
                        </div>
                        <button className="btn btn-secondary" onClick={() => void copySecure("totp")}>
                          <Copy size={14} />
                          Copiar 2FA
                        </button>
                      </div>
                    )}

                    {detail.overview.urls.length > 0 && (
                      <div className="secret-field-card" style={{ display: "block" }}>
                        <div className="field-label" style={{ marginBottom: 6 }}>Sitios vinculados</div>
                        {detail.overview.urls.map((u) => (
                          <div key={u} className="mono" style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>
                            {u}
                          </div>
                        ))}
                      </div>
                    )}

                    {detail.secret.notes && (
                      <div className="secret-field-card" style={{ display: "block" }}>
                        <div className="field-label" style={{ marginBottom: 6 }}>Notas</div>
                        <div style={{ whiteSpace: "pre-wrap", fontSize: 13 }}>{detail.secret.notes}</div>
                      </div>
                    )}

                    <PasswordHistoryPopover entries={detail.secret.password_history ?? []} />
                  </>
                )}

                {detail.secret.kind === "note" && (
                  <div className="secret-field-card" style={{ display: "block" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 10 }}>
                      <span className="field-label">Nota segura</span>
                      <button className="btn btn-secondary" onClick={() => void copySecure("note_body")}>
                        <Copy size={14} />
                        Copiar nota
                      </button>
                    </div>
                    <pre className="mono" style={{ margin: 0, whiteSpace: "pre-wrap", fontSize: 13 }}>
                      {detail.secret.body}
                    </pre>
                  </div>
                )}

                {detail.secret.kind === "card" && (
                  <>
                    <div className="secret-field-card">
                      <div>
                        <div className="field-label">Número de tarjeta ({detail.secret.cardholder_name})</div>
                        <div className="mono">
                          {revealSecret ? detail.secret.card_number : detail.overview.subtitle}
                        </div>
                      </div>
                      <div style={{ display: "flex", gap: 6 }}>
                        <button className="btn btn-secondary" onClick={() => setRevealSecret((v) => !v)}>
                          {revealSecret ? <EyeOff size={14} /> : <Eye size={14} />}
                        </button>
                        <button className="btn btn-primary" onClick={() => void copySecure("card_number")}>
                          <Copy size={14} />
                          Copiar número
                        </button>
                      </div>
                    </div>

                    <div className="secret-field-card">
                      <div>
                        <div className="field-label">Vencimiento y CVV</div>
                        <div className="mono">
                          {detail.secret.exp_month}/{detail.secret.exp_year} · CVV:{" "}
                          {revealSecret ? detail.secret.cvv : "•••"}
                        </div>
                      </div>
                      <button className="btn btn-secondary" onClick={() => void copySecure("cvv")}>
                        <Copy size={14} />
                        Copiar CVV
                      </button>
                    </div>
                  </>
                )}
              </div>
            )}
          </main>
        </>
      )}

      <ItemEditorDrawer
        open={editorOpen}
        editingItem={editingTarget}
        folders={folders}
        onClose={() => setEditorOpen(false)}
        onSaved={(saved) => {
          void loadIndex();
          setSelectedId(saved.id);
          void loadSelectedDetail(saved.id);
        }}
      />

      <PasswordGeneratorModal open={generatorOpen} onClose={() => setGeneratorOpen(false)} />
    </div>
  );
}
