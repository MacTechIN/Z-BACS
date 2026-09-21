// Z-BACS Agent shell. Deliberately small: it shows what the backend reports and never
// invents state. Flows arrive with Z-1.G.2 / G.3 / G.9.
const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

const PERMISSION_WORDS = {
  "read-only": "주인이 읽기만 허용해 둔 파일입니다.",
  edit: "주인이 편집까지 허용해 둔 파일입니다.",
  deny: "주인이 열람을 막아 둔 파일입니다.",
};

const seen = new Map();

function render() {
  const list = document.getElementById("files");
  const empty = document.getElementById("empty");
  const template = document.getElementById("file-card");

  list.replaceChildren();
  for (const file of seen.values()) {
    const card = template.content.cloneNode(true);
    const tag = card.querySelector('[data-role="tag"]');
    const headline = card.querySelector('[data-role="headline"]');
    const note = card.querySelector('[data-role="note"]');
    const size = card.querySelector('[data-role="size"]');
    const action = card.querySelector('[data-role="action"]');

    if (file.sealed) {
      tag.textContent = "잠김";
      headline.textContent = "잠긴 파일입니다. 주인에게 물어봐야 열 수 있어요.";
      note.textContent = PERMISSION_WORDS[file.default_permission] ?? "";
      size.textContent = humanSize(file.size);
      action.textContent = "열람 요청";
      action.disabled = true;
      action.title = "승인 요청 기능은 다음 단계에서 연결됩니다.";
    } else {
      tag.textContent = "열 수 없음";
      tag.classList.add("tag--error");
      headline.textContent = file.problem ?? "이 파일은 열 수 없습니다.";
      note.textContent = "";
      size.textContent = "";
      action.textContent = "확인";
      action.disabled = true;
    }
    list.append(card);
  }

  const any = seen.size > 0;
  list.hidden = !any;
  empty.hidden = any;
}

function humanSize(bytes) {
  if (bytes === null || bytes === undefined) return "";
  const units = ["B", "KB", "MB", "GB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

function accept(files) {
  for (const file of files) seen.set(file.path, file);
  render();
  const lines = [...seen.values()].map((f) => `${f.path}\n  ${f.detail ?? f.problem ?? ""}`);
  document.getElementById("dev").textContent = lines.join("\n");
}

async function main() {
  await listen("zbacs://opened", (event) => accept(event.payload));
  accept(await invoke("take_pending"));
  const caps = await invoke("capabilities");
  console.info("agent capabilities", caps);
  render();
}

main().catch((e) => {
  document.getElementById("dev").textContent = `시작 중 문제가 발생했습니다: ${e}`;
});
