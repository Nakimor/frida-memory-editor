import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import threading
import json
import frida

# =====================================================================================
#  JS ENGINE (внедряется в целевой процесс через Frida)
# =====================================================================================
JS_ENGINE = r"""
var matches = [];
var currentType = 'int32';
var freezeTimer = null;
var watchList = [];   // { address(str), type, name, value, frozen }

var TYPE_SIZE = { byte:1, int16:2, int32:4, int64:8, float:4, double:8 };

function bytesToHex(ptrVal, len) {
    return Array.from(new Uint8Array(ptrVal.readByteArray(len)))
        .map(b => b.toString(16).padStart(2, '0')).join(' ');
}

function asciiBytes(s) {
    var arr = [];
    for (var i = 0; i < s.length; i++) arr.push(s.charCodeAt(i) & 0xFF);
    return arr;
}

function readVal(addr, type) {
    try {
        var p = ptr(addr);
        switch (type) {
            case 'byte':   return p.readU8();
            case 'int16':  return p.readS16();
            case 'int32':  return p.readInt();
            case 'int64':  return p.readS64().toString();
            case 'float':  return parseFloat(p.readFloat().toFixed(4));
            case 'double': return parseFloat(p.readDouble().toFixed(6));
            case 'string': return p.readUtf8String(48);
        }
    } catch (e) { return null; }
}

function writeVal(addr, type, val) {
    try {
        var p = ptr(addr);
        switch (type) {
            case 'byte':   p.writeU8(parseInt(val) & 0xFF); break;
            case 'int16':  p.writeS16(parseInt(val)); break;
            case 'int32':  p.writeInt(parseInt(val)); break;
            case 'int64':  p.writeS64(int64(val)); break;
            case 'float':  p.writeFloat(parseFloat(val)); break;
            case 'double': p.writeDouble(parseFloat(val)); break;
            case 'string': p.writeUtf8String(String(val)); break;
        }
        return true;
    } catch (e) { return false; }
}

function valueToPattern(type, val) {
    var buf;
    switch (type) {
        case 'byte':   buf = Memory.alloc(1); buf.writeU8(parseInt(val) & 0xFF); return bytesToHex(buf, 1);
        case 'int16':  buf = Memory.alloc(2); buf.writeS16(parseInt(val)); return bytesToHex(buf, 2);
        case 'int32':  buf = Memory.alloc(4); buf.writeInt(parseInt(val)); return bytesToHex(buf, 4);
        case 'int64':  buf = Memory.alloc(8); buf.writeS64(int64(val)); return bytesToHex(buf, 8);
        case 'float':  buf = Memory.alloc(4); buf.writeFloat(parseFloat(val)); return bytesToHex(buf, 4);
        case 'double': buf = Memory.alloc(8); buf.writeDouble(parseFloat(val)); return bytesToHex(buf, 8);
        case 'string':
            var bytes = asciiBytes(String(val));
            if (bytes.length === 0) return null;
            return bytes.map(b => b.toString(16).padStart(2, '0')).join(' ');
    }
    return null;
}

rpc.exports = {

    // ---------- поиск ----------
    firstScanExact: function (dataType, val) {
        matches = [];
        currentType = dataType;
        var pattern = valueToPattern(dataType, val);
        if (!pattern) return { count: 0 };

        Process.enumerateRanges({ protection: 'rw-', coalesce: true }).forEach(range => {
            try {
                Memory.scanSync(range.base, range.size, pattern).forEach(m => {
                    matches.push({ address: m.address, lastValue: readVal(m.address, currentType) });
                });
            } catch (e) {}
        });
        return { count: matches.length };
    },

    // Поиск "неизвестного" значения — ограничен по объёму памяти ради стабильности/скорости
    firstScanUnknown: function (dataType) {
        matches = [];
        currentType = dataType;
        var size = TYPE_SIZE[dataType];
        if (!size || dataType === 'int64' || dataType === 'string') {
            return { error: 'unsupported' };
        }
        var CAP = 8 * 1024 * 1024; // 8 MB — safety cap, экспериментальный режим
        var scanned = 0;

        var ranges = Process.enumerateRanges({ protection: 'rw-', coalesce: true });
        for (var i = 0; i < ranges.length && scanned < CAP; i++) {
            var r = ranges[i];
            var bytes = Math.min(r.size, CAP - scanned);
            var alignedLen = bytes - (bytes % size);
            if (alignedLen <= 0) { scanned += r.size; continue; }
            try {
                var raw = r.base.readByteArray(alignedLen);
                var view;
                if (dataType === 'byte') view = new Uint8Array(raw);
                else if (dataType === 'int16') view = new Int16Array(raw);
                else if (dataType === 'int32') view = new Int32Array(raw);
                else if (dataType === 'float') view = new Float32Array(raw);
                else if (dataType === 'double') view = new Float64Array(raw);
                for (var j = 0; j < view.length; j++) {
                    var v = view[j];
                    if (dataType === 'float' || dataType === 'double') v = parseFloat(v.toFixed(4));
                    matches.push({ address: r.base.add(j * size), lastValue: v });
                }
            } catch (e) {}
            scanned += r.size;
        }
        return { count: matches.length, cappedMB: Math.round(CAP / 1024 / 1024) };
    },

    nextScan: function (mode, targetVal, targetVal2) {
        if (matches.length === 0) return 0;
        var isFloatType = (currentType === 'float' || currentType === 'double');
        var t1 = isFloatType ? parseFloat(targetVal) : parseInt(targetVal);
        var t2 = (targetVal2 !== undefined && targetVal2 !== null && targetVal2 !== '')
            ? (isFloatType ? parseFloat(targetVal2) : parseInt(targetVal2)) : null;

        matches = matches.filter(item => {
            var cur = readVal(item.address, currentType);
            if (cur === null) return false;
            var prev = item.lastValue;
            var ok = false;
            if (mode === 'eq') ok = (cur == t1);
            else if (mode === 'neq') ok = (cur != t1);
            else if (mode === 'inc') ok = (cur > prev);
            else if (mode === 'dec') ok = (cur < prev);
            else if (mode === 'changed') ok = (cur != prev);
            else if (mode === 'unchanged') ok = (cur == prev);
            else if (mode === 'between') ok = (t2 !== null && cur >= t1 && cur <= t2);

            if (ok) item.lastValue = cur;
            return ok;
        });
        return matches.length;
    },

    getMatches: function (offset, limit) {
        return matches.slice(offset, offset + limit).map(m => ({
            address: m.address.toString(),
            value: readVal(m.address, currentType)
        }));
    },

    setValueAt: function (address, type, val) {
        return writeVal(address, type, val);
    },

    setValues: function (newVal) {
        matches.forEach(m => writeVal(m.address, currentType, newVal));
        return matches.length;
    },

    // ---------- заморозка всех текущих результатов поиска ----------
    toggleFreeze: function (enable, val) {
        _restartFreezeTimer();
        return _freezeAllEnabled;
    },

    // ---------- список наблюдения (cheat table) ----------
    watchAdd: function (address, type, name, value) {
        watchList.push({ address: address, type: type, name: name || address, value: value, frozen: false });
        return watchList.length;
    },

    watchRemove: function (address) {
        watchList = watchList.filter(w => w.address !== address);
        return watchList.length;
    },

    watchRename: function (address, name) {
        var w = watchList.find(w => w.address === address);
        if (w) w.name = name;
        return !!w;
    },

    watchSetValue: function (address, val) {
        var w = watchList.find(w => w.address === address);
        if (!w) return false;
        w.value = val;
        return writeVal(w.address, w.type, val);
    },

    watchToggleFreeze: function (address, enable) {
        var w = watchList.find(w => w.address === address);
        if (!w) return false;
        w.frozen = enable;
        return true;
    },

    watchList: function () {
        return watchList.map(w => ({
            address: w.address, type: w.type, name: w.name, frozen: w.frozen,
            value: readVal(w.address, w.type)
        }));
    },

    watchImport: function (entries) {
        watchList = entries.map(e => ({ address: e.address, type: e.type, name: e.name, value: e.value, frozen: !!e.frozen }));
        return watchList.length;
    }
};

var _freezeAllEnabled = false;
var _freezeAllVal = null;

rpc.exports.toggleFreeze = function (enable, val) {
    _freezeAllEnabled = enable;
    _freezeAllVal = val;
    return _freezeAllEnabled;
};

function _restartFreezeTimer() {
    if (freezeTimer !== null) { clearInterval(freezeTimer); freezeTimer = null; }
    freezeTimer = setInterval(function () {
        if (_freezeAllEnabled && _freezeAllVal !== null) {
            matches.forEach(m => writeVal(m.address, currentType, _freezeAllVal));
        }
        watchList.forEach(w => { if (w.frozen) writeVal(w.address, w.type, w.value); });
    }, 50);
}
_restartFreezeTimer();
"""

# =====================================================================================
#  ПАЛИТРА
# =====================================================================================
BG_MAIN = "#130b16"
BG_CARD = "#1d1220"
BG_INPUT = "#2a1a2e"
BG_INPUT_HOVER = "#3a2440"
FG_MAIN = "#f3e6ef"
FG_DIM = "#b494ac"
ACCENT_BLUE = "#ff4fa0"       # основной розовый акцент
ACCENT_BLUE_LIGHT = "#ff8ac2"  # акцент при наведении
ACCENT_GREEN = "#7be8a4"
ACCENT_RED = "#ff4d6d"
ACCENT_YELLOW = "#ffc978"
ACCENT_MAUVE = "#c77dff"
BORDER_COLOR = "#3d2740"
TEXT_ON_ACCENT = "#1c0f19"

TYPES = ["byte", "int16", "int32", "int64", "float", "double", "string"]
TYPES_UNKNOWN_OK = ["byte", "int16", "int32", "float", "double"]

TYPE_INFO = {
    "byte":   "1 байт, целое БЕЗ знака.  Диапазон: 0 … 255",
    "int16":  "2 байта, целое со знаком.  Диапазон: -32 768 … 32 767",
    "int32":  "4 байта, целое со знаком.  Диапазон: -2 147 483 648 … 2 147 483 647\n(самый частый тип для HP, патронов, монет)",
    "int64":  "8 байт, целое со знаком.  Огромный диапазон — для денег/опыта в больших числах",
    "float":  "4 байта, дробное число.  Точность ~6-7 значащих цифр",
    "double": "8 байт, дробное число.  Точность ~15 значащих цифр (точнее float)",
    "string": "Текст в ASCII, читается/пишется до 48 байт. Кириллица и юникод не поддерживаются",
}

SCAN_INFO = {
    "first_exact":   "Первый поиск: сканирует ВСЮ доступную для записи память (rw-)\n"
                      "и ищет точное совпадение с числом из поля «Значение».\n"
                      "Именно с него обычно и начинают поиск.",
    "first_unknown": "Поиск без знания значения: запоминает АБСОЛЮТНО ВСЕ числа\n"
                      "в ограниченной области памяти (~8 МБ, иначе слишком долго и тяжело).\n"
                      "После — меняете значение в игре (например, тратите патрон)\n"
                      "и жмёте «Изменилось» / «Уменьшилось», чтобы сузить список.",
    "eq":        "Оставляет только адреса, где ТЕКУЩЕЕ значение равно\nчислу в поле «Значение».",
    "neq":       "Оставляет адреса, где текущее значение НЕ равно\nчислу в поле «Значение».",
    "inc":       "Оставляет адреса, где значение ВЫРОСЛО по сравнению\nс прошлым сканом. Поле «Значение» не используется.",
    "dec":       "Оставляет адреса, где значение УМЕНЬШИЛОСЬ по сравнению\nс прошлым сканом. Поле «Значение» не используется.",
    "changed":   "Оставляет адреса, значение которых ЛЮБЫМ образом\nизменилось с прошлого скана.",
    "unchanged": "Оставляет адреса, значение которых НЕ изменилось\nс прошлого скана — полезно, если что-то осталось прежним.",
    "between":   "Оставляет адреса, где текущее значение лежит между\n«Значение» и «до» (включительно). Нужно заполнить оба поля.",
}


class ToolTip:
    """Простая всплывающая подсказка при наведении на виджет."""

    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, _event=None):
        if self.tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 6
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        tk.Label(self.tip, text=self.text, justify="left", bg="#0d070f", fg=FG_MAIN,
                 relief="solid", borderwidth=1, font=("Segoe UI", 8), padx=6, pady=4,
                 wraplength=300).pack()

    def hide(self, _event=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class ScrollableFrame(tk.Frame):
    """Вертикально прокручиваемый контейнер. Гарантирует, что даже на маленьком
    экране весь контент вкладки остаётся доступен через скролл, а не обрезается
    за пределами окна."""

    def __init__(self, parent, bg=BG_MAIN):
        super().__init__(parent, bg=bg)
        canvas = tk.Canvas(self, bg=bg, highlightthickness=0)
        vbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vbar.set)

        self.inner = tk.Frame(canvas, bg=bg)
        window_id = canvas.create_window((0, 0), window=self.inner, anchor="nw")

        def _on_inner_configure(_event):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _on_canvas_configure(event):
            canvas.itemconfig(window_id, width=event.width)

        self.inner.bind("<Configure>", _on_inner_configure)
        canvas.bind("<Configure>", _on_canvas_configure)

        def _mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def _bind_wheel(_e):
            canvas.bind_all("<MouseWheel>", _mousewheel)

        def _unbind_wheel(_e):
            canvas.unbind_all("<MouseWheel>")

        canvas.bind("<Enter>", _bind_wheel)
        canvas.bind("<Leave>", _unbind_wheel)

        canvas.pack(side="left", fill="both", expand=True)
        vbar.pack(side="right", fill="y")


class MemoryEditorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Memory Editor — Frida Cheat Table")
        self.root.geometry("820x620")
        self.root.minsize(700, 460)
        self.root.configure(bg=BG_MAIN)

        self.device = None
        self.session = None
        self.api = None
        self.device_mode = tk.StringVar(value="usb")
        self.processes_map = {}
        self.all_proc_labels = []
        self.match_offset = 0
        self.match_total = 0
        self.freeze_all_on = False
        self.watch_autorefresh = tk.BooleanVar(value=True)
        self._watch_job = None
        self.busy = False

        self.setup_styles()
        self.create_menu()
        self.create_widgets()
        self.refresh_processes()

    # ---------------------------------------------------------------- styles
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background=BG_MAIN, foreground=FG_MAIN, font=("Segoe UI", 9))
        style.configure("TFrame", background=BG_MAIN)
        style.configure("Card.TFrame", background=BG_CARD)

        style.configure("TLabelframe", background=BG_CARD, bordercolor=BORDER_COLOR,
                         relief="solid", borderwidth=1)
        style.configure("TLabelframe.Label", background=BG_CARD, foreground=ACCENT_BLUE,
                         font=("Segoe UI", 9, "bold"))

        # ---- обычные кнопки: плоские, с мягкой розовой обводкой и hover ----
        style.configure("TButton", background=BG_INPUT, foreground=FG_MAIN,
                         bordercolor=BORDER_COLOR, borderwidth=1, relief="flat",
                         focuscolor="none", padding=(10, 6), font=("Segoe UI", 9))
        style.map("TButton",
                  background=[("active", BG_INPUT_HOVER), ("pressed", BG_INPUT_HOVER)],
                  bordercolor=[("active", ACCENT_BLUE), ("!active", BORDER_COLOR)])

        # ---- акцентная (розовая) кнопка ----
        style.configure("Accent.TButton", background=ACCENT_BLUE, foreground=TEXT_ON_ACCENT,
                         bordercolor=ACCENT_BLUE, borderwidth=1, relief="flat",
                         font=("Segoe UI", 9, "bold"), padding=(12, 6), focuscolor="none")
        style.map("Accent.TButton",
                  background=[("active", ACCENT_BLUE_LIGHT), ("pressed", ACCENT_BLUE_LIGHT)],
                  bordercolor=[("active", ACCENT_BLUE_LIGHT)])

        # ---- кнопка опасного действия ----
        style.configure("Danger.TButton", background=ACCENT_RED, foreground=TEXT_ON_ACCENT,
                         bordercolor=ACCENT_RED, borderwidth=1, relief="flat",
                         font=("Segoe UI", 9, "bold"), padding=(12, 6), focuscolor="none")
        style.map("Danger.TButton",
                  background=[("active", "#ff8098"), ("pressed", "#ff8098")],
                  bordercolor=[("active", "#ff8098")])

        # ---- поля ввода: плоские, розовая рамка в фокусе ----
        style.configure("TEntry", fieldbackground=BG_INPUT, foreground=FG_MAIN,
                         insertcolor=ACCENT_BLUE, bordercolor=BORDER_COLOR,
                         lightcolor=BG_INPUT, darkcolor=BG_INPUT,
                         borderwidth=1, relief="flat", padding=6)
        style.map("TEntry",
                  bordercolor=[("focus", ACCENT_BLUE), ("!focus", BORDER_COLOR)],
                  lightcolor=[("focus", ACCENT_BLUE)], darkcolor=[("focus", ACCENT_BLUE)])

        style.configure("TCombobox", fieldbackground=BG_INPUT, background=BG_INPUT,
                         foreground=FG_MAIN, arrowcolor=ACCENT_BLUE, bordercolor=BORDER_COLOR,
                         lightcolor=BG_INPUT, darkcolor=BG_INPUT, borderwidth=1, padding=5)
        style.map("TCombobox",
                  fieldbackground=[("readonly", BG_INPUT)],
                  foreground=[("readonly", FG_MAIN)],
                  bordercolor=[("focus", ACCENT_BLUE), ("!focus", BORDER_COLOR)])
        # выпадающий список комбобокса (не всегда поддерживается на всех ОС, но пробуем)
        self.root.option_add("*TCombobox*Listbox.background", BG_INPUT)
        self.root.option_add("*TCombobox*Listbox.foreground", FG_MAIN)
        self.root.option_add("*TCombobox*Listbox.selectBackground", ACCENT_BLUE)
        self.root.option_add("*TCombobox*Listbox.selectForeground", TEXT_ON_ACCENT)

        style.configure("Treeview", background=BG_CARD, foreground=FG_MAIN,
                         fieldbackground=BG_CARD, rowheight=25, borderwidth=0,
                         font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=BG_INPUT, foreground=ACCENT_BLUE,
                         font=("Segoe UI", 9, "bold"), borderwidth=1, relief="flat")
        style.map("Treeview.Heading", background=[("active", BG_INPUT_HOVER)])
        style.map("Treeview", background=[("selected", "#4a2350")],
                   foreground=[("selected", "#ffffff")])

        style.configure("Vertical.TScrollbar", background=BG_INPUT, bordercolor=BG_CARD,
                         arrowcolor=ACCENT_BLUE, troughcolor=BG_CARD, relief="flat", borderwidth=0)
        style.map("Vertical.TScrollbar", background=[("active", BG_INPUT_HOVER)])

        style.configure("TNotebook", background=BG_MAIN, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG_INPUT, foreground=FG_DIM,
                         padding=(16, 8), font=("Segoe UI", 9, "bold"), borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", BG_CARD)],
                  foreground=[("selected", ACCENT_BLUE)])

        style.configure("TCheckbutton", background=BG_CARD, foreground=FG_MAIN, focuscolor="none")
        style.map("TCheckbutton", foreground=[("selected", ACCENT_BLUE)])
        style.configure("TRadiobutton", background=BG_CARD, foreground=FG_MAIN, focuscolor="none")
        style.map("TRadiobutton", foreground=[("selected", ACCENT_BLUE)])
        style.configure("Horizontal.TProgressbar", background=ACCENT_BLUE, troughcolor=BG_INPUT,
                         borderwidth=0, lightcolor=ACCENT_BLUE, darkcolor=ACCENT_BLUE)

    # ---------------------------------------------------------------- menu
    def create_menu(self):
        menubar = tk.Menu(self.root, bg=BG_INPUT, fg=FG_MAIN, activebackground=BORDER_COLOR,
                           activeforeground=FG_MAIN, tearoff=0)
        file_menu = tk.Menu(menubar, tearoff=0, bg=BG_INPUT, fg=FG_MAIN,
                             activebackground=BORDER_COLOR, activeforeground=FG_MAIN)
        file_menu.add_command(label="💾 Сохранить таблицу...", command=self.save_table)
        file_menu.add_command(label="📂 Загрузить таблицу...", command=self.load_table)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.root.destroy)
        menubar.add_cascade(label="Файл", menu=file_menu)

        help_menu = tk.Menu(menubar, tearoff=0, bg=BG_INPUT, fg=FG_MAIN,
                             activebackground=BORDER_COLOR, activeforeground=FG_MAIN)
        help_menu.add_command(label="О программе", command=lambda: messagebox.showinfo(
            "О программе",
            "Memory Editor на базе Frida.\n"
            "Инструмент для анализа и модификации памяти собственных приложений "
            "(аналог Cheat Engine / GameGuardian).\n\n"
            "Используйте ответственно — соблюдайте правила онлайн-игр и сервисов."))
        menubar.add_cascade(label="Справка", menu=help_menu)
        self.root.config(menu=menubar)

    # ---------------------------------------------------------------- widgets
    def create_widgets(self):
        # ---- 1. Подключение ----
        frame_conn = ttk.LabelFrame(self.root, text=" 1. Подключение ", padding=8)
        frame_conn.pack(fill="x", padx=10, pady=(8, 4))

        row0 = tk.Frame(frame_conn, bg=BG_CARD)
        row0.pack(fill="x")
        ttk.Radiobutton(row0, text="📱 USB (Android)", variable=self.device_mode, value="usb",
                         command=self.refresh_processes).pack(side="left", padx=(0, 10))
        ttk.Radiobutton(row0, text="💻 Локальный (PC)", variable=self.device_mode, value="local",
                         command=self.refresh_processes).pack(side="left")

        row1 = tk.Frame(frame_conn, bg=BG_CARD)
        row1.pack(fill="x", pady=(6, 0))
        ttk.Label(row1, text="Фильтр:", background=BG_CARD).pack(side="left")
        self.entry_filter = ttk.Entry(row1, width=16)
        self.entry_filter.pack(side="left", padx=4)
        self.entry_filter.bind("<KeyRelease>", self.apply_process_filter)

        self.combo_procs = ttk.Combobox(row1, width=36, state="readonly")
        self.combo_procs.pack(side="left", padx=4)

        ttk.Button(row1, text="🔄", width=3, command=self.refresh_processes).pack(side="left", padx=2)
        ttk.Button(row1, text="⚡ Подключиться", style="Accent.TButton",
                   command=self.connect_target).pack(side="left", padx=6)

        self.lbl_status = tk.Label(row1, text="OFFLINE", bg=BG_CARD, fg=ACCENT_RED,
                                    font=("Segoe UI", 9, "bold"))
        self.lbl_status.pack(side="left", padx=8)

        # ---- альтернативный способ: spawn (Frida сама запускает процесс) ----
        row2 = tk.Frame(frame_conn, bg=BG_CARD)
        row2.pack(fill="x", pady=(6, 0))
        ttk.Label(row2, text="или Spawn-запуск:", background=BG_CARD).pack(side="left")
        self.entry_spawn = ttk.Entry(row2, width=30)
        self.entry_spawn.pack(side="left", padx=4)
        self.entry_spawn.insert(0, "com.example.app")

        btn_spawn = ttk.Button(row2, text="🚀 Запустить и внедриться", command=self.connect_spawn)
        btn_spawn.pack(side="left", padx=4)
        ToolTip(btn_spawn,
                "Обычный «Подключиться» цепляется к УЖЕ запущенному процессу (attach)\n"
                "и иногда падает с ошибкой вроде «unable to perform ptrace pokedata».\n\n"
                "Spawn-запуск вместо этого сам стартует приложение и внедряет скрипт\n"
                "ДО первой инструкции — это надёжнее и часто обходит эту ошибку.\n\n"
                "USB: введите идентификатор пакета, например com.example.app\n"
                "(если приложение уже запущено — сначала закройте/сверните его).\n"
                "Локально (PC): введите полный путь к исполняемому файлу.")

        # Прогресс-бар всегда занимает своё место (даже когда не крутится) —
        # это не даёт остальному интерфейсу "прыгать" при busy-состоянии.
        self.progress = ttk.Progressbar(frame_conn, mode="indeterminate")
        self.progress.pack(fill="x", pady=(6, 0))

        # ---- Notebook ----
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=4)

        self.tab_scan = tk.Frame(self.notebook, bg=BG_MAIN)
        self.tab_watch = tk.Frame(self.notebook, bg=BG_MAIN)
        self.notebook.add(self.tab_scan, text="🔍 Сканер памяти")
        self.notebook.add(self.tab_watch, text="📌 Список наблюдения")

        self.build_scanner_tab()
        self.build_watchlist_tab()

    # ---------------------------------------------------------------- scanner tab
    def build_scanner_tab(self):
        scroll = ScrollableFrame(self.tab_scan, bg=BG_MAIN)
        scroll.pack(fill="both", expand=True)
        parent = scroll.inner

        frame_search = ttk.LabelFrame(parent, text=" 2. Поиск значения ", padding=8)
        frame_search.pack(fill="x", padx=2, pady=4)

        r0 = tk.Frame(frame_search, bg=BG_CARD)
        r0.pack(fill="x")
        ttk.Label(r0, text="Тип:", background=BG_CARD).pack(side="left")
        self.combo_type = ttk.Combobox(r0, values=TYPES, width=8, state="readonly")
        self.combo_type.current(2)
        self.combo_type.pack(side="left", padx=4)

        ttk.Label(r0, text="Значение:", background=BG_CARD).pack(side="left", padx=(8, 0))
        self.entry_val = ttk.Entry(r0, width=12)
        self.entry_val.pack(side="left", padx=4)

        ttk.Label(r0, text="до (для «Между»):", background=BG_CARD).pack(side="left")
        self.entry_val2 = ttk.Entry(r0, width=10)
        self.entry_val2.pack(side="left", padx=4)

        btn_first = ttk.Button(r0, text="🔍 Первый поиск", style="Accent.TButton",
                                command=self.first_scan)
        btn_first.pack(side="left", padx=(10, 2))
        ToolTip(btn_first, SCAN_INFO["first_exact"])

        btn_unknown = ttk.Button(r0, text="❓ Неизвестное знач.", command=self.first_scan_unknown)
        btn_unknown.pack(side="left", padx=2)
        ToolTip(btn_unknown, SCAN_INFO["first_unknown"])

        # Подсказка про диапазон текущего типа данных — обновляется при выборе типа
        self.lbl_type_hint = tk.Label(frame_search, text=TYPE_INFO["int32"], bg=BG_CARD,
                                       fg=FG_DIM, font=("Segoe UI", 8), justify="left", anchor="w")
        self.lbl_type_hint.pack(fill="x", pady=(4, 0))

        r1 = tk.Frame(frame_search, bg=BG_CARD)
        r1.pack(fill="x", pady=(8, 0))
        for text, mode in [("Равно (==)", "eq"), ("Не равно (!=)", "neq"),
                            ("Больше (>)", "inc"), ("Меньше (<)", "dec"),
                            ("Изменилось", "changed"), ("Не изменилось", "unchanged"),
                            ("Между", "between")]:
            btn = ttk.Button(r1, text=text, command=lambda m=mode: self.next_scan(m))
            btn.pack(side="left", padx=2)
            ToolTip(btn, SCAN_INFO[mode])

        self.lbl_count = tk.Label(frame_search, text="Найдено адресов: 0", bg=BG_CARD,
                                   fg=ACCENT_BLUE, font=("Segoe UI", 9, "bold"))
        self.lbl_count.pack(pady=(6, 0))

        # ---- таблица результатов ----
        frame_list = ttk.LabelFrame(parent, text=" 3. Адреса в RAM (двойной клик = изменить) ",
                                     padding=6)
        frame_list.pack(fill="both", expand=True, padx=2, pady=4)

        tree_container = tk.Frame(frame_list, bg=BG_CARD)
        tree_container.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(tree_container, columns=("Addr", "Value"), show="headings", height=6)
        self.tree.heading("Addr", text="Адрес памяти")
        self.tree.heading("Value", text="Значение")
        self.tree.column("Addr", width=280, anchor="center")
        self.tree.column("Value", width=200, anchor="center")
        self.tree.bind("<Double-1>", self.on_result_double_click)
        self.tree.bind("<Button-3>", self.on_result_right_click)

        scrollbar = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.result_menu = tk.Menu(self.root, tearoff=0, bg=BG_INPUT, fg=FG_MAIN,
                                    activebackground=BORDER_COLOR, activeforeground=FG_MAIN)
        self.result_menu.add_command(label="📋 Скопировать адрес", command=self.copy_selected_address)
        self.result_menu.add_command(label="📌 Добавить в список наблюдения",
                                      command=self.add_selected_to_watch)

        r2 = tk.Frame(frame_list, bg=BG_CARD)
        r2.pack(fill="x", pady=(4, 0))
        ttk.Button(r2, text="⬇ Показать ещё", command=self.load_more_matches).pack(side="left")

        # ---- модификация ----
        frame_action = ttk.LabelFrame(parent, text=" 4. Модификация всех найденных ", padding=8)
        frame_action.pack(fill="x", padx=2, pady=4)

        ttk.Label(frame_action, text="Новое значение:", background=BG_CARD).grid(row=0, column=0, padx=4)
        self.entry_new_val = ttk.Entry(frame_action, width=16)
        self.entry_new_val.grid(row=0, column=1, padx=4)
        ttk.Button(frame_action, text="✏️ Записать во все", command=self.set_value_all).grid(
            row=0, column=2, padx=6)

        self.btn_freeze = tk.Button(
            frame_action, text="❄️ ЗАМОРОЗИТЬ ВСЕ", bg=BG_INPUT, fg=FG_MAIN,
            activebackground=BORDER_COLOR, activeforeground=FG_MAIN,
            font=("Segoe UI", 8, "bold"), relief="flat", bd=1, padx=10, pady=2,
            command=self.toggle_freeze_all)
        self.btn_freeze.grid(row=0, column=3, padx=6)

        self.combo_type.bind("<<ComboboxSelected>>", self._on_type_change)

    def _on_type_change(self, _event=None):
        t = self.combo_type.get()
        self.lbl_type_hint.config(text=TYPE_INFO.get(t, ""))

    # ---------------------------------------------------------------- watchlist tab
    def build_watchlist_tab(self):
        scroll = ScrollableFrame(self.tab_watch, bg=BG_MAIN)
        scroll.pack(fill="both", expand=True)
        parent = scroll.inner

        frame_top = tk.Frame(parent, bg=BG_MAIN)
        frame_top.pack(fill="x", padx=2, pady=6)

        ttk.Button(frame_top, text="➕ Добавить вручную", command=self.watch_add_manual).pack(side="left", padx=2)
        ttk.Button(frame_top, text="✏ Изменить значение", command=self.watch_edit_value).pack(side="left", padx=2)
        ttk.Button(frame_top, text="✎ Переименовать", command=self.watch_rename).pack(side="left", padx=2)
        ttk.Button(frame_top, text="🗑 Удалить", style="Danger.TButton",
                   command=self.watch_remove_selected).pack(side="left", padx=2)
        ttk.Checkbutton(frame_top, text="Автообновление", variable=self.watch_autorefresh).pack(
            side="left", padx=12)

        frame_list = ttk.LabelFrame(parent, text=" Cheat Table ", padding=6)
        frame_list.pack(fill="both", expand=True, padx=2, pady=4)

        tree_container = tk.Frame(frame_list, bg=BG_CARD)
        tree_container.pack(fill="both", expand=True)

        cols = ("Name", "Addr", "Type", "Value", "Frozen")
        self.watch_tree = ttk.Treeview(tree_container, columns=cols, show="headings", height=8)
        headers = {"Name": "Название", "Addr": "Адрес", "Type": "Тип",
                   "Value": "Значение", "Frozen": "Заморожено"}
        widths = {"Name": 160, "Addr": 220, "Type": 70, "Value": 120, "Frozen": 90}
        for c in cols:
            self.watch_tree.heading(c, text=headers[c])
            self.watch_tree.column(c, width=widths[c], anchor="center")
        self.watch_tree.bind("<Double-1>", self.on_watch_double_click)
        self.watch_tree.bind("<Button-3>", self.on_watch_right_click)

        scrollbar = ttk.Scrollbar(tree_container, orient="vertical", command=self.watch_tree.yview)
        self.watch_tree.configure(yscrollcommand=scrollbar.set)
        self.watch_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.watch_menu = tk.Menu(self.root, tearoff=0, bg=BG_INPUT, fg=FG_MAIN,
                                   activebackground=BORDER_COLOR, activeforeground=FG_MAIN)
        self.watch_menu.add_command(label="❄️ Заморозить / разморозить", command=self.watch_toggle_freeze_selected)
        self.watch_menu.add_command(label="📋 Скопировать адрес", command=self.watch_copy_address)
        self.watch_menu.add_command(label="🗑 Удалить", command=self.watch_remove_selected)

    # ================================================================== helpers
    def run_async(self, work_fn, on_done=None, on_error=None, busy_label=None, animate=True):
        """Выполняет work_fn в отдельном потоке, не блокируя интерфейс.

        animate=False используется для лёгких фоновых вызовов (например,
        автообновление списка наблюдения), чтобы прогресс-бар не мигал
        и интерфейс не "дёргался" каждые полторы секунды.
        """
        if animate:
            self.set_busy(True)

        def wrapper():
            try:
                result = work_fn()
            except Exception as e:
                self.root.after(0, lambda: self._finish_async(on_error, e, is_error=True, animate=animate))
                return
            self.root.after(0, lambda: self._finish_async(on_done, result, is_error=False, animate=animate))

        threading.Thread(target=wrapper, daemon=True).start()

    def _finish_async(self, cb, value, is_error, animate=True):
        if animate:
            self.set_busy(False)
        if is_error:
            if cb:
                cb(value)
            else:
                messagebox.showerror("Ошибка", str(value))
        elif cb:
            cb(value)

    def set_busy(self, is_busy):
        # Прогресс-бар всегда занимает своё место в раскладке (упакован один раз
        # при создании) — здесь только запускаем/останавливаем анимацию,
        # без pack/pack_forget, чтобы соседние виджеты не смещались.
        self.busy = is_busy
        if is_busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    # ================================================================== процессы
    def refresh_processes(self):
        def work():
            if self.device_mode.get() == "usb":
                dev = frida.get_usb_device(timeout=3)
                apps = [a for a in dev.enumerate_applications() if a.pid and a.pid > 0]
                apps.sort(key=lambda a: a.name.lower())
                mapping = {f"{a.name} ({a.identifier}) [PID: {a.pid}]": a.pid for a in apps}
            else:
                dev = frida.get_local_device()
                procs = [p for p in dev.enumerate_processes() if p.pid > 0]
                procs.sort(key=lambda p: p.name.lower())
                mapping = {f"{p.name} [PID: {p.pid}]": p.pid for p in procs}
            return dev, mapping

        def done(result):
            dev, mapping = result
            self.device = dev
            self.processes_map = mapping
            self.all_proc_labels = list(mapping.keys())
            self.apply_process_filter()

        def error(e):
            self.combo_procs["values"] = [f"Ошибка: {e}"]

        self.run_async(work, done, error)

    def apply_process_filter(self, _event=None):
        query = self.entry_filter.get().strip().lower()
        labels = [l for l in self.all_proc_labels if query in l.lower()] if query else self.all_proc_labels
        self.combo_procs["values"] = labels or ["Ничего не найдено"]
        if labels:
            self.combo_procs.current(0)

    # ================================================================== подключение
    def _on_connected(self, session, api, status_text="ONLINE"):
        self.session, self.api = session, api
        self.freeze_all_on = False
        self.btn_freeze.config(text="❄️ ЗАМОРОЗИТЬ ВСЕ", bg=BG_INPUT, fg=FG_MAIN)
        self.lbl_status.config(text=status_text, fg=ACCENT_GREEN)
        self.lbl_count.config(text="Найдено адресов: 0")
        self.match_offset = 0
        self.match_total = 0
        self.update_tree([])
        self.start_watch_autorefresh()

    def _detach_current(self):
        if self.session:
            try:
                self.session.detach()
            except Exception:
                pass

    def connect_target(self):
        """Обычный attach к уже запущенному процессу из списка."""
        selected = self.combo_procs.get()
        if not selected or selected not in self.processes_map:
            messagebox.showwarning("Внимание", "Выберите процесс из списка!")
            return
        pid = self.processes_map[selected]

        def work():
            self._detach_current()
            try:
                self.device.disable_spawn_gating()
            except Exception:
                pass
            session = self.device.attach(pid)
            script = session.create_script(JS_ENGINE)
            script.load()
            return session, script.exports_sync

        def done(result):
            session, api = result
            self._on_connected(session, api, "ONLINE")

        def error(e):
            self.lbl_status.config(text="OFFLINE", fg=ACCENT_RED)
            msg = str(e)
            if "ptrace" in msg.lower():
                msg += ("\n\nЭта ошибка часто означает, что процесс защищён от attach "
                        "(антиотладка/SELinux). Попробуйте Spawn-запуск ниже — "
                        "он стартует приложение и внедряет скрипт до его старта, "
                        "минуя эту проблему.")
            messagebox.showerror("Ошибка Frida", msg)

        self.run_async(work, done, error)

    def connect_spawn(self):
        """Альтернативный способ: Frida сама запускает процесс (spawn) и внедряется
        до выполнения первой инструкции — надёжнее attach для защищённых процессов,
        часто решает ошибку 'unable to perform ptrace pokedata'."""
        target = self.entry_spawn.get().strip()
        if not target:
            messagebox.showwarning("Внимание", "Введите идентификатор пакета (USB) или путь к программе (PC).")
            return
        mode = self.device_mode.get()

        def work():
            # Важно: берём СВЕЖИЙ Device на каждую попытку, а не переиспользуем
            # закешированный self.device — если до этого была неудачная попытка
            # attach (например, ptrace-ошибка) или включён spawn gating, старый
            # объект устройства может остаться в "подвисшем" состоянии и спокойно
            # работающий `frida -U -f pkg` в отдельном терминале это не отражает,
            # т.к. CLI-утилита каждый раз создаёт новое соединение с нуля.
            self.device = (frida.get_usb_device(timeout=10) if mode == "usb"
                            else frida.get_local_device())
            try:
                self.device.disable_spawn_gating()
            except Exception:
                pass
            self._detach_current()
            pid = self.device.spawn(target) if mode == "usb" else self.device.spawn([target])
            session = self.device.attach(pid)
            script = session.create_script(JS_ENGINE)
            script.load()
            self.device.resume(pid)
            return session, script.exports_sync, pid

        def done(result):
            session, api, pid = result
            self._on_connected(session, api, f"ONLINE (spawn, PID {pid})")

        def error(e):
            self.lbl_status.config(text="OFFLINE", fg=ACCENT_RED)
            msg = str(e)
            if "timed out" in msg.lower() or "timeout" in msg.lower():
                msg += (
                    "\n\nЭто известная особенность spawn+resume на Android: Frida сама\n"
                    "не успевает отследить момент запуска приложения. Частые причины:\n"
                    "• версия frida-server на телефоне не совпадает с версией\n"
                    "  пакета frida в Python (проверьте: frida --version на ПК\n"
                    "  и версию бинарника frida-server на устройстве);\n"
                    "• неверный/неточный идентификатор пакета (регистр важен);\n"
                    "• приложение долго стартует или требует доп. разрешений.\n\n"
                    "sad.")
            messagebox.showerror("Ошибка Frida (spawn)", msg)

        self.run_async(work, done, error)

    def require_api(self):
        if not self.api:
            messagebox.showwarning("Ошибка", "Сначала подключитесь к процессу!")
            return False
        return True

    # ================================================================== сканирование
    def first_scan(self):
        if not self.require_api():
            return
        val = self.entry_val.get().strip()
        if not val:
            messagebox.showwarning("Ошибка", "Введите значение!")
            return
        t_type = self.combo_type.get()

        def work():
            return self.api.first_scan_exact(t_type, val)

        def done(result):
            self.match_offset = 0
            self.match_total = result.get("count", 0)
            self.lbl_count.config(text=f"Найдено адресов: {self.match_total}")
            self.load_more_matches(reset=True)

        self.run_async(work, done)

    def first_scan_unknown(self):
        if not self.require_api():
            return
        t_type = self.combo_type.get()
        if t_type not in TYPES_UNKNOWN_OK:
            messagebox.showwarning(
                "Недоступно",
                "Поиск неизвестного значения поддерживается только для: "
                + ", ".join(TYPES_UNKNOWN_OK))
            return
        if not messagebox.askyesno(
                "Экспериментальный режим",
                "Поиск неизвестного значения сканирует область памяти без фильтра "
                "по значению и ограничен ~8 МБ ради стабильности. Результат может быть "
                "неполным на больших процессах. Продолжить?"):
            return

        def work():
            return self.api.first_scan_unknown(t_type)

        def done(result):
            if result.get("error"):
                messagebox.showwarning("Не поддерживается", "Этот тип не поддерживается для данного режима.")
                return
            self.match_offset = 0
            self.match_total = result.get("count", 0)
            self.lbl_count.config(text=f"Найдено адресов: {self.match_total} (ограничение ~{result.get('cappedMB', 8)} МБ)")
            self.load_more_matches(reset=True)

        self.run_async(work, done, busy_label="Сканирование...")

    def next_scan(self, mode):
        if not self.require_api():
            return
        if self.match_total == 0:
            messagebox.showinfo("Пусто", "Сначала выполните первый поиск.")
            return
        val = self.entry_val.get().strip() or "0"
        val2 = self.entry_val2.get().strip() if mode == "between" else None
        if mode == "between" and not val2:
            messagebox.showwarning("Ошибка", "Укажите второе значение диапазона (поле 'до').")
            return

        def work():
            return self.api.next_scan(mode, val, val2)

        def done(count):
            self.match_offset = 0
            self.match_total = count
            self.lbl_count.config(text=f"Осталось адресов: {count}")
            self.load_more_matches(reset=True)

        self.run_async(work, done)

    def load_more_matches(self, reset=False):
        if not self.api:
            return
        if reset:
            self.match_offset = 0
        offset = self.match_offset
        limit = 100

        def work():
            return self.api.get_matches(offset, limit)

        def done(rows):
            self.match_offset += len(rows)
            self.update_tree(rows, append=not reset)

        self.run_async(work, done)

    def update_tree(self, rows, append=False):
        if not append:
            for r in self.tree.get_children():
                self.tree.delete(r)
        for m in rows:
            self.tree.insert("", "end", values=(m["address"], m["value"]))

    # ---- работа с выделенной строкой результатов ----
    def on_result_double_click(self, _event):
        sel = self.tree.selection()
        if not sel or not self.api:
            return
        addr, old_val = self.tree.item(sel[0], "values")
        new_val = simpledialog.askstring("Изменить значение", f"Адрес: {addr}\nНовое значение:",
                                          initialvalue=str(old_val))
        if new_val is None:
            return
        t_type = self.combo_type.get()

        def work():
            return self.api.set_value_at(addr, t_type, new_val)

        def done(ok):
            if ok:
                self.tree.item(sel[0], values=(addr, new_val))
            else:
                messagebox.showerror("Ошибка", "Не удалось записать значение.")

        self.run_async(work, done)

    def on_result_right_click(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self.result_menu.tk_popup(event.x_root, event.y_root)

    def copy_selected_address(self):
        sel = self.tree.selection()
        if not sel:
            return
        addr = self.tree.item(sel[0], "values")[0]
        self.root.clipboard_clear()
        self.root.clipboard_append(addr)

    def add_selected_to_watch(self):
        sel = self.tree.selection()
        if not sel or not self.api:
            return
        addr, val = self.tree.item(sel[0], "values")
        t_type = self.combo_type.get()
        name = simpledialog.askstring("Название", "Имя для списка наблюдения:", initialvalue=addr)
        if name is None:
            return

        def work():
            return self.api.watch_add(addr, t_type, name, val)

        def done(_result):
            self.refresh_watchlist()

        self.run_async(work, done)

    # ================================================================== модификация всех
    def set_value_all(self):
        if not self.require_api():
            return
        val = self.entry_new_val.get().strip()
        if not val:
            messagebox.showwarning("Ошибка", "Введите новое значение!")
            return

        def work():
            return self.api.set_values(val)

        def done(count):
            messagebox.showinfo("Успех", f"Записано значение [{val}] в {count} адресов!")
            self.load_more_matches(reset=True)

        self.run_async(work, done)

    def toggle_freeze_all(self):
        if not self.require_api():
            return
        if not self.freeze_all_on:
            val = self.entry_new_val.get().strip()
            if not val:
                messagebox.showwarning("Ошибка", "Задайте значение в поле 'Новое значение' для заморозки!")
                return

            def work():
                return self.api.toggle_freeze(True, val)

            def done(_r):
                self.freeze_all_on = True
                self.btn_freeze.config(text="🔥 РАЗМОРОЗИТЬ", bg=ACCENT_RED, fg=TEXT_ON_ACCENT)

            self.run_async(work, done)
        else:
            def work():
                return self.api.toggle_freeze(False, "0")

            def done(_r):
                self.freeze_all_on = False
                self.btn_freeze.config(text="❄️ ЗАМОРОЗИТЬ ВСЕ", bg=BG_INPUT, fg=FG_MAIN)

            self.run_async(work, done)

    # ================================================================== watch list
    def watch_add_manual(self):
        if not self.require_api():
            return
        addr = simpledialog.askstring("Адрес", "Введите адрес (например 0x7f1234abcd):")
        if not addr:
            return
        t_type = simpledialog.askstring("Тип", f"Тип ({'/'.join(TYPES)}):", initialvalue="int32")
        if t_type not in TYPES:
            messagebox.showwarning("Ошибка", "Неизвестный тип данных.")
            return
        name = simpledialog.askstring("Название", "Имя:", initialvalue=addr) or addr

        def work():
            return self.api.watch_add(addr, t_type, name, "0")

        def done(_r):
            self.refresh_watchlist()

        self.run_async(work, done)

    def watch_edit_value(self):
        sel = self.watch_tree.selection()
        if not sel or not self.api:
            return
        name, addr, t_type, old_val, _frozen = self.watch_tree.item(sel[0], "values")
        new_val = simpledialog.askstring("Изменить значение", f"{name}\nНовое значение:",
                                          initialvalue=str(old_val))
        if new_val is None:
            return

        def work():
            return self.api.watch_set_value(addr, new_val)

        def done(_r):
            self.refresh_watchlist()

        self.run_async(work, done)

    def watch_rename(self):
        sel = self.watch_tree.selection()
        if not sel or not self.api:
            return
        name, addr, *_ = self.watch_tree.item(sel[0], "values")
        new_name = simpledialog.askstring("Переименовать", "Новое название:", initialvalue=name)
        if not new_name:
            return

        def work():
            return self.api.watch_rename(addr, new_name)

        def done(_r):
            self.refresh_watchlist()

        self.run_async(work, done)

    def watch_remove_selected(self):
        sel = self.watch_tree.selection()
        if not sel or not self.api:
            return
        _name, addr, *_ = self.watch_tree.item(sel[0], "values")

        def work():
            return self.api.watch_remove(addr)

        def done(_r):
            self.refresh_watchlist()

        self.run_async(work, done)

    def watch_toggle_freeze_selected(self):
        sel = self.watch_tree.selection()
        if not sel or not self.api:
            return
        _name, addr, _t, _v, frozen = self.watch_tree.item(sel[0], "values")
        new_state = frozen != "✓"

        def work():
            return self.api.watch_toggle_freeze(addr, new_state)

        def done(_r):
            self.refresh_watchlist()

        self.run_async(work, done)

    def watch_copy_address(self):
        sel = self.watch_tree.selection()
        if not sel:
            return
        _name, addr, *_ = self.watch_tree.item(sel[0], "values")
        self.root.clipboard_clear()
        self.root.clipboard_append(addr)

    def on_watch_double_click(self, _event):
        self.watch_edit_value()

    def on_watch_right_click(self, event):
        row = self.watch_tree.identify_row(event.y)
        if row:
            self.watch_tree.selection_set(row)
            self.watch_menu.tk_popup(event.x_root, event.y_root)

    def refresh_watchlist(self, animate=True):
        if not self.api:
            return

        def work():
            return self.api.watch_list()

        def done(entries):
            # Обновляем строки "на месте" (iid = адрес) вместо удаления и
            # пересоздания всей таблицы — иначе при каждом автообновлении
            # сбрасывались выделение и позиция скролла, и список "прыгал".
            existing = set(self.watch_tree.get_children())
            seen = set()
            for e in entries:
                iid = e["address"]
                seen.add(iid)
                vals = (e["name"], e["address"], e["type"], e["value"],
                        "✓" if e["frozen"] else "—")
                if self.watch_tree.exists(iid):
                    self.watch_tree.item(iid, values=vals)
                else:
                    self.watch_tree.insert("", "end", iid=iid, values=vals)
            for iid in existing - seen:
                self.watch_tree.delete(iid)

        self.run_async(work, done, animate=animate)

    def start_watch_autorefresh(self):
        if self._watch_job:
            self.root.after_cancel(self._watch_job)

        def tick():
            if self.api and self.watch_autorefresh.get() and not self.busy:
                self.refresh_watchlist(animate=False)
            self._watch_job = self.root.after(1500, tick)

        self._watch_job = self.root.after(1500, tick)

    # ================================================================== save/load table
    def save_table(self):
        if not self.api:
            messagebox.showwarning("Ошибка", "Нет активного подключения.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                             filetypes=[("Cheat Table", "*.json")])
        if not path:
            return

        def work():
            return self.api.watch_list()

        def done(entries):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(entries, f, ensure_ascii=False, indent=2)
            messagebox.showinfo("Готово", f"Таблица сохранена: {path}")

        self.run_async(work, done)

    def load_table(self):
        if not self.require_api():
            return
        path = filedialog.askopenfilename(filetypes=[("Cheat Table", "*.json")])
        if not path:
            return
        with open(path, "r", encoding="utf-8") as f:
            entries = json.load(f)

        def work():
            return self.api.watch_import(entries)

        def done(_count):
            self.refresh_watchlist()
            messagebox.showinfo("Готово", f"Загружено записей: {len(entries)}")

        self.run_async(work, done)


if __name__ == "__main__":
    root = tk.Tk()
    app = MemoryEditorApp(root)
    root.mainloop()