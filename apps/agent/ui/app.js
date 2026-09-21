// Z-BACS Agent shell.
//
// Every word the person reads lives in this file and in index.html, so `tools/ux-lint.sh` can
// check all of it at once: no forbidden vocabulary (U-5) and no text input (U-6). The backend
// hands over machine values ("biometric", "volatile_key_store") and never sentences.
//
// Flows still ahead: sealing (Z-1.G.3) and requesting access (Z-1.G.9). The buttons for those
// are disabled and say so rather than pretending.
const invoke = window.__TAURI__.core.invoke;
const listen = window.__TAURI__.event.listen;

const PERMISSION_WORDS = {
  "read-only": "주인이 읽기만 허용해 둔 파일입니다.",
  edit: "주인이 편집까지 허용해 둔 파일입니다.",
  deny: "주인이 열람을 막아 둔 파일입니다.",
};

// The one choice of the whole first run (Z-1.U.7, ADR-0006).
const CHOICES = {
  biometric: {
    icon: "☺",
    title: "얼굴이나 지문으로 확인하고 승인",
    note: "허락할 때마다 이 컴퓨터가 본인인지 한 번 확인합니다.",
    unavailable: "이 컴퓨터에는 얼굴·지문·PIN 확인이 준비돼 있지 않아요.",
  },
  this_device: {
    icon: "◉",
    title: "이 기기에서 바로 승인",
    note: "이 컴퓨터에서 누르기만 하면 됩니다. 중요한 허락은 그래도 한 번 더 확인해요.",
    unavailable: "이 컴퓨터에서는 쓸 수 없어요.",
  },
};

// Only the two outcomes that change what the person can expect are shown. The rest
// (account_on_chain, device_enrolment, recovery_code) are ours to finish, not theirs to know —
// ux_principles §2 — so they go to the developer panel instead.
const NOTES = {
  volatile_key_store: "이 컴퓨터에는 안전한 보관함이 없어서, 앱을 다시 켜면 준비를 한 번 더 해야 해요.",
  software_signer: "이 컴퓨터에는 전용 보안 칩이 없어요. 쓰는 데는 문제가 없지만 보호는 조금 약합니다.",
};

// Why a dropped file cannot be locked. Every one of these says what the person can do next
// (ux_principles rule 6), because "안 됩니다" alone leaves them stuck.
const FILE_PROBLEMS = {
  is_folder: "폴더는 아직 잠글 수 없어요. 파일 하나를 골라 주세요.",
  already_locked: "이 파일은 이미 잠겨 있어요.",
  empty: "빈 파일이에요. 내용이 있는 파일을 골라 주세요.",
  output_exists: "같은 이름으로 잠근 파일이 이미 있어요. 그 파일을 옮기거나 지운 뒤 다시 해 주세요.",
  missing: "그 파일을 찾을 수 없어요.",
  unreadable: "그 파일을 읽을 수 없어요.",
  not_set_up: "먼저 준비를 마쳐야 해요.",
  no_locked_copy: "잠근 파일이 옆에 없어서 원본을 지우지 않았어요.",
  failed: "잠그지 못했어요. 잠시 뒤 다시 시도해 주세요.",
};

const SETUP_PROBLEMS = {
  cancelled: "확인이 취소됐어요. 다시 눌러 주세요.",
  unsupported: "이 방법은 이 컴퓨터에서 쓸 수 없어요. 다른 방법을 골라 주세요.",
  no_signer: "이 컴퓨터에서는 아직 지원하지 않는 방식이에요.",
  failed: "준비하지 못했어요. 잠시 뒤 다시 시도해 주세요.",
};

const seen = new Map();
let status = null;

// ---------------------------------------------------------------- screens

const SCREENS = ["welcome", "choice", "working", "done", "blocked", "home", "seal", "sealed"];

function show(name) {
  for (const screen of SCREENS) {
    document.getElementById(`screen-${screen}`).hidden = screen !== name;
  }
  // Tell the Agent which screen this is: if a first run goes wrong on someone's machine, the
  // log is the only record of how far they got.
  invoke("ui_screen", { name }).catch(() => {});
}

function route() {
  if (!status) return;
  if (!status.can_set_up) {
    document.getElementById("blocked-line").textContent =
      SETUP_PROBLEMS[status.blocked] ?? SETUP_PROBLEMS.failed;
    show("blocked");
  } else if (status.onboarded) {
    show("home");
  } else {
    show("welcome");
  }
}

// ---------------------------------------------------------------- setup

function renderChoices() {
  const list = document.getElementById("choices");
  const template = document.getElementById("choice-card");
  list.replaceChildren();

  for (const choice of status.choices) {
    const words = CHOICES[choice.id];
    if (!words) continue;
    const node = template.content.cloneNode(true);
    const button = node.querySelector('[data-role="choice"]');
    node.querySelector('[data-role="icon"]').textContent = words.icon;
    node.querySelector('[data-role="title"]').textContent = words.title;
    node.querySelector('[data-role="note"]').textContent = choice.available
      ? words.note
      : words.unavailable;

    if (!choice.available) {
      button.disabled = true;
    } else {
      if (choice.id === status.recommended) {
        node.querySelector('[data-role="badge"]').hidden = false;
        button.classList.add("choice--recommended");
      }
      button.addEventListener("click", () => completeSetup(choice.id));
    }
    list.append(node);
  }
}

async function completeSetup(style) {
  show("working");
  try {
    status = await invoke("complete_setup", { style });
  } catch (problem) {
    document.getElementById("blocked-line").textContent =
      SETUP_PROBLEMS[problem] ?? SETUP_PROBLEMS.failed;
    show("blocked");
    return;
  }
  const chosen = CHOICES[status.style];
  document.getElementById("done-line").textContent = chosen
    ? `이제부터 "${chosen.title}"으로 허락합니다.`
    : "이제 파일을 잠그고 보낼 수 있어요.";

  const notes = document.getElementById("done-notes");
  notes.replaceChildren();
  for (const id of status.pending) {
    if (!NOTES[id]) continue;
    const line = document.createElement("p");
    line.className = "notes__line";
    line.textContent = NOTES[id];
    notes.append(line);
  }
  showDev();
  show("done");
}

// ---------------------------------------------------------------- locking a file

// What the lock screen currently holds. `candidate` is null until a file is accepted, which is
// also what keeps the [잠그기] button from existing before there is anything to lock.
const sealing = { candidate: null, permission: "read_only", ttl: "hour", opens: "once", result: null };

// A row of preset buttons where exactly one is pressed. Takes the element, not its id, so the
// markup check in tools/ux-lint.sh can see which ids this file actually depends on.
function segment(group, onPick) {
  for (const button of group.querySelectorAll(".segment__btn")) {
    button.addEventListener("click", () => {
      for (const other of group.querySelectorAll(".segment__btn")) {
        other.setAttribute("aria-pressed", String(other === button));
      }
      onPick(button.dataset.value);
    });
  }
}

function sealProblem(id) {
  document.getElementById("drop-line").textContent = FILE_PROBLEMS[id] ?? FILE_PROBLEMS.failed;
  document.getElementById("seal-options").hidden = true;
  sealing.candidate = null;
}

async function offerFile(path) {
  let candidate;
  try {
    candidate = await invoke("examine_path", { path });
  } catch {
    sealProblem("unreadable");
    return;
  }
  if (!candidate.ok) {
    sealProblem(candidate.problem);
    return;
  }
  sealing.candidate = candidate;
  document.getElementById("drop-line").textContent = `${candidate.name} · ${humanSize(candidate.size)}`;
  document.getElementById("seal-options").hidden = false;
}

async function doSeal() {
  if (!sealing.candidate) return;
  show("working");
  document.getElementById("working-line").textContent = "파일을 잠그고 있어요.";
  try {
    sealing.result = await invoke("seal_file", {
      request: {
        path: sealing.candidate.path,
        permission: sealing.permission,
        ttl: sealing.ttl,
        opens: sealing.opens,
      },
    });
  } catch (problem) {
    sealProblem(problem);
    show("seal");
    return;
  }
  document.getElementById("sealed-name").textContent = sealing.result.output_name;
  document.getElementById("shred-area").hidden = false;
  document.getElementById("shred-confirm").hidden = true;
  showDev();
  show("sealed");
}

function openSealScreen() {
  sealing.candidate = null;
  sealing.result = null;
  document.getElementById("drop-line").textContent = "여기에 끌어다 놓기";
  document.getElementById("seal-options").hidden = true;
  show("seal");
}

// ---------------------------------------------------------------- files

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
  showDev();
}

function showDev() {
  const lines = [...seen.values()].map((f) => `${f.path}\n  ${f.detail ?? f.problem ?? ""}`);
  if (sealing.result) lines.unshift(`sealed ${JSON.stringify(sealing.result)}`);
  if (status) lines.unshift(`setup ${JSON.stringify(status)}`);
  document.getElementById("dev").textContent = lines.join("\n");
}

// ---------------------------------------------------------------- start

async function main() {
  document.getElementById("start").addEventListener("click", () => {
    renderChoices();
    show("choice");
  });
  document.getElementById("done").addEventListener("click", () => show("home"));
  document.getElementById("to-seal").addEventListener("click", openSealScreen);
  document.getElementById("seal-back").addEventListener("click", () => show("home"));
  document.getElementById("do-seal").addEventListener("click", doSeal);
  document.getElementById("sealed-done").addEventListener("click", () => show("home"));

  segment(document.getElementById("perm"), (v) => (sealing.permission = v));
  segment(document.getElementById("ttl"), (v) => (sealing.ttl = v));
  segment(document.getElementById("opens"), (v) => (sealing.opens = v));

  document.getElementById("pick").addEventListener("click", async () => {
    const picked = await window.__TAURI__.dialog.open({ multiple: false, directory: false });
    if (picked) await offerFile(picked);
  });

  // Erasing the original is not undoable, so it takes a second, deliberate tap.
  document.getElementById("shred").addEventListener("click", () => {
    document.getElementById("shred-area").hidden = true;
    document.getElementById("shred-confirm").hidden = false;
  });
  document.getElementById("shred-no").addEventListener("click", () => {
    document.getElementById("shred-area").hidden = false;
    document.getElementById("shred-confirm").hidden = true;
  });
  document.getElementById("shred-yes").addEventListener("click", async () => {
    try {
      await invoke("shred_original", { path: sealing.result.original });
      document.getElementById("shred-confirm").hidden = true;
      const done = document.createElement("p");
      done.className = "notes__line";
      done.textContent = "원본을 지웠어요.";
      document.getElementById("shred-confirm").after(done);
    } catch (problem) {
      const line = document.createElement("p");
      line.className = "notes__line";
      line.textContent = FILE_PROBLEMS[problem] ?? FILE_PROBLEMS.failed;
      document.getElementById("shred-confirm").after(line);
      document.getElementById("shred-confirm").hidden = true;
    }
  });

  // Show the drop area reacting, so it is obvious the window will take the file.
  const drop = document.getElementById("drop");
  await listen("tauri://drag-enter", () => drop.classList.add("drop--over"));
  await listen("tauri://drag-leave", () => drop.classList.remove("drop--over"));

  // A file dropped anywhere on the window goes to the lock screen. Dropping is the way most
  // people will reach for, so it must not depend on first finding the right button.
  await listen("tauri://drag-drop", async (event) => {
    drop.classList.remove("drop--over");
    const paths = event.payload?.paths ?? [];
    if (paths.length === 0 || !status?.onboarded) return;
    openSealScreen();
    await offerFile(paths[0]);
  });
  document.getElementById("retry").addEventListener("click", async () => {
    status = await invoke("setup_status");
    route();
  });

  await listen("zbacs://opened", (event) => accept(event.payload));
  status = await invoke("setup_status");
  route();

  accept(await invoke("take_pending"));
  const caps = await invoke("capabilities");
  console.info("agent capabilities", caps);
  render();
}

main().catch((e) => {
  document.getElementById("dev").textContent = `시작 중 문제가 발생했습니다: ${e}`;
  invoke("ui_problem", { detail: String(e) }).catch(() => {});
});
