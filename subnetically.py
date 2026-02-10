import tkinter as tk
from tkinter import ttk, messagebox
import ipaddress
import random
import math

# ----------------------------
# Helper functions (IPv4 only)
# ----------------------------

def parse_ip_cidr(ip_str, cidr_str):
    """Parse IP and CIDR and return IPv4Interface, with validation."""
    ip_str = ip_str.strip()
    cidr_str = cidr_str.strip().lstrip('/')  # allow "/24" or "24"
    if not cidr_str.isdigit():
        raise ValueError("CIDR must be an integer from 0 to 32.")
    prefix = int(cidr_str)
    if prefix < 0 or prefix > 32:
        raise ValueError("CIDR prefix must be between 0 and 32.")
    try:
        iface = ipaddress.IPv4Interface(f"{ip_str}/{prefix}")
    except Exception:
        raise ValueError("Invalid IPv4 address.")
    return iface

def subnet_stats_from_interface(iface: ipaddress.IPv4Interface):
    """Return key subnet info for a given IPv4Interface."""
    net = iface.network
    network_id = net.network_address
    broadcast = net.broadcast_address
    prefix = net.prefixlen
    total_addresses = net.num_addresses

    # Usable host count: classical rules
    if prefix <= 30:
        usable_hosts = max(0, total_addresses - 2)
        first_usable = ipaddress.IPv4Address(int(network_id) + 1)
        last_usable = ipaddress.IPv4Address(int(broadcast) - 1)
    elif prefix == 31:
        # RFC 3021: /31 point-to-point, both addresses usable
        usable_hosts = 2
        first_usable = network_id
        last_usable = broadcast
    else:  # /32
        usable_hosts = 1
        first_usable = network_id
        last_usable = network_id

    mask = net.netmask
    wildcard = ipaddress.IPv4Address(int(ipaddress.IPv4Address("255.255.255.255")) - int(mask))

    # Next network: add block size to network_id (wrap handled by ipaddress)
    block_size = 2 ** (32 - prefix)
    next_network_addr_int = int(network_id) + block_size
    if next_network_addr_int <= int(ipaddress.IPv4Address("255.255.255.255")):
        next_network = ipaddress.IPv4Network((next_network_addr_int, prefix))
    else:
        next_network = None  # no next network in IPv4 space

    return {
        "network": net,
        "network_id": network_id,
        "first_usable": first_usable,
        "last_usable": last_usable,
        "broadcast": broadcast,
        "mask": mask,
        "wildcard": wildcard,
        "prefix": prefix,
        "total_addresses": total_addresses,
        "usable_hosts": usable_hosts,
        "next_network": next_network,
    }

def smallest_prefix_for_hosts(required_hosts: int):
    """Find the smallest CIDR that supports required_hosts (usable), applying classic rules.
    Returns prefix, usable_hosts, total_addresses.
    """
    if required_hosts <= 0:
        raise ValueError("Required hosts must be positive.")
    # Special cases
    if required_hosts == 1:
        return 32, 1, 1
    if required_hosts == 2:
        return 31, 2, 2

    # For usable_hosts >= required, usable = 2^(host_bits) - 2
    # Find minimal host_bits such that 2^host_bits - 2 >= required_hosts
    host_bits = 0
    while (2 ** host_bits) - 2 < required_hosts:
        host_bits += 1
        if host_bits > 32:
            raise ValueError("Host requirement exceeds IPv4 address space.")
    prefix = 32 - host_bits
    total = 2 ** host_bits
    usable = total - 2
    return prefix, usable, total

def format_ip(ip):
    return str(ip) if ip is not None else "N/A"

def random_interface(min_prefix=20, max_prefix=30):
    """Generate a random IPv4Interface suitable for practice."""
    prefix = random.randint(min_prefix, max_prefix)
    # Random private ranges for practicality
    private_blocks = [
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    ]
    block = random.choice(private_blocks)
    # Choose a random network within the block with given prefix
    # Get a random network_id aligned to prefix
    host_bits = 32 - prefix
    block_start = int(block.network_address)
    block_end = int(block.broadcast_address)
    # Compute number of available blocks of this size in the chosen private block
    block_size = 2 ** host_bits
    start_aligned = (block_start + (random.randint(0, (block_end - block_start) // block_size) * block_size))
    net = ipaddress.IPv4Network((start_aligned, prefix))
    # Pick a random IP inside net
    rand_offset = random.randint(0, net.num_addresses - 1)
    ip = ipaddress.IPv4Address(int(net.network_address) + rand_offset)
    return ipaddress.IPv4Interface(f"{ip}/{prefix}")

def network_contains(parent: ipaddress.IPv4Network, child: ipaddress.IPv4Network):
    """Return True if 'child' is entirely within 'parent'."""
    return int(child.network_address) >= int(parent.network_address) and int(child.broadcast_address) <= int(parent.broadcast_address)

def generate_parent_subnets(base="10.0.0.0/16", count=7):
    """Generate a list of parent subnets under a base network for practice mode 2."""
    base_net = ipaddress.IPv4Network(base)
    # Choose prefixes between /18 and /22 under base
    parents = []
    for _ in range(count):
        pfx = random.randint(18, 22)
        # pick a random subnet of base with prefix pfx
        candidates = list(base_net.subnets(new_prefix=pfx))
        parent = random.choice(candidates)
        parents.append(parent)
    # Deduplicate (in rare case random picks match)
    unique = []
    seen = set()
    for p in parents:
        if (p.network_address, p.prefixlen) not in seen:
            unique.append(p)
            seen.add((p.network_address, p.prefixlen))
    return unique

def generate_child_candidate(parents):
    """Generate a child candidate that fits under at least one of the parents."""
    parent = random.choice(parents)
    # Choose child prefix 2-4 deeper
    child_prefix = min(32, parent.prefixlen + random.randint(2, 6))
    # pick a random child subnet of parent with this prefix
    candidates = list(parent.subnets(new_prefix=child_prefix))
    child = random.choice(candidates)
    return child, parent

# ----------------------------
# Tkinter App
# ----------------------------

class SubnetApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Subnet Calculator & Practice")
        self.geometry("980x680")
        self.minsize(900, 640)

        style = ttk.Style(self)
        style.theme_use("clam")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        self._build_calculator_tab()
        self._build_host_to_cidr_tab()
        self._build_practice1_tab()
        self._build_practice2_tab()

    # ----------------------------
    # Tab 1: Calculator (IP + CIDR)
    # ----------------------------
    def _build_calculator_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Subnet calculator")

        inputs = ttk.LabelFrame(frame, text="Inputs")
        inputs.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(inputs, text="IP address:").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        self.calc_ip_entry = ttk.Entry(inputs, width=20)
        self.calc_ip_entry.grid(row=0, column=1, sticky="w", padx=6, pady=6)
        self.calc_ip_entry.insert(0, "192.168.10.25")

        ttk.Label(inputs, text="CIDR (e.g., 24):").grid(row=0, column=2, sticky="w", padx=6, pady=6)
        self.calc_cidr_entry = ttk.Entry(inputs, width=10)
        self.calc_cidr_entry.grid(row=0, column=3, sticky="w", padx=6, pady=6)
        self.calc_cidr_entry.insert(0, "24")

        self.calc_btn = ttk.Button(inputs, text="Calculate", command=self._do_calc)
        self.calc_btn.grid(row=0, column=4, padx=10, pady=6)

        self.calc_result = ttk.LabelFrame(frame, text="Results")
        self.calc_result.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Results grid
        labels = [
            ("Network ID:", "calc_network"),
            ("Netmask:", "calc_mask"),
            ("Wildcard mask:", "calc_wildcard"),
            ("First usable:", "calc_first"),
            ("Last usable:", "calc_last"),
            ("Broadcast:", "calc_bcast"),
            ("Prefix length:", "calc_prefix"),
            ("Total addresses:", "calc_total"),
            ("Usable hosts:", "calc_usable"),
            ("Next network:", "calc_next"),
        ]

        self.calc_vars = {}
        for i, (title, key) in enumerate(labels):
            ttk.Label(self.calc_result, text=title).grid(row=i, column=0, sticky="w", padx=6, pady=6)
            var = tk.StringVar(value="")
            self.calc_vars[key] = var
            ttk.Entry(self.calc_result, textvariable=var, width=40, state="readonly").grid(row=i, column=1, sticky="w", padx=6, pady=6)

        tip = ttk.Label(self.calc_result, text="Note: /31 treats both addresses as usable; /32 is a single host.")
        tip.grid(row=len(labels), column=0, columnspan=2, sticky="w", padx=6, pady=4)

    def _do_calc(self):
        try:
            iface = parse_ip_cidr(self.calc_ip_entry.get(), self.calc_cidr_entry.get())
            stats = subnet_stats_from_interface(iface)
            self.calc_vars["calc_network"].set(str(stats["network"]))
            self.calc_vars["calc_mask"].set(str(stats["mask"]))
            self.calc_vars["calc_wildcard"].set(str(stats["wildcard"]))
            self.calc_vars["calc_first"].set(format_ip(stats["first_usable"]))
            self.calc_vars["calc_last"].set(format_ip(stats["last_usable"]))
            self.calc_vars["calc_bcast"].set(format_ip(stats["broadcast"]))
            self.calc_vars["calc_prefix"].set(str(stats["prefix"]))
            self.calc_vars["calc_total"].set(str(stats["total_addresses"]))
            self.calc_vars["calc_usable"].set(str(stats["usable_hosts"]))
            self.calc_vars["calc_next"].set(str(stats["next_network"]) if stats["next_network"] else "N/A")
        except Exception as e:
            messagebox.showerror("Input error", str(e))

    # ----------------------------
    # Tab 2: Host requirement -> CIDR with 10% padding
    # ----------------------------
    def _build_host_to_cidr_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Hosts → CIDR (+10%)")

        inputs = ttk.LabelFrame(frame, text="Inputs")
        inputs.pack(fill=tk.X, padx=10, pady=10)

        ttk.Label(inputs, text="Required hosts:").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        self.hosts_entry = ttk.Entry(inputs, width=18)
        self.hosts_entry.grid(row=0, column=1, sticky="w", padx=6, pady=6)
        self.hosts_entry.insert(0, "100")

        self.hosts_btn = ttk.Button(inputs, text="Suggest CIDR", command=self._do_hosts_to_cidr)
        self.hosts_btn.grid(row=0, column=2, padx=10, pady=6)

        results = ttk.LabelFrame(frame, text="Results")
        results.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.hosts_vars = {
            "padded": tk.StringVar(),
            "prefix": tk.StringVar(),
            "usable": tk.StringVar(),
            "total": tk.StringVar(),
            "mask": tk.StringVar(),
            "example": tk.StringVar(),
        }

        rows = [
            ("Required (with +10% padding):", "padded"),
            ("Suggested CIDR prefix:", "prefix"),
            ("Netmask:", "mask"),
            ("Total addresses:", "total"),
            ("Usable hosts:", "usable"),
            ("Example network:", "example"),
        ]
        for i, (label, key) in enumerate(rows):
            ttk.Label(results, text=label).grid(row=i, column=0, sticky="w", padx=6, pady=6)
            ttk.Entry(results, textvariable=self.hosts_vars[key], width=40, state="readonly").grid(row=i, column=1, sticky="w", padx=6, pady=6)

    def _do_hosts_to_cidr(self):
        try:
            req = int(self.hosts_entry.get().strip())
            if req <= 0:
                raise ValueError("Required hosts must be positive.")
            padded = math.ceil(req * 1.10)
            prefix, usable, total = smallest_prefix_for_hosts(padded)
            mask = ipaddress.IPv4Network(f"0.0.0.0/{prefix}").netmask
            # Create example network starting at 10.0.0.0
            example_net = ipaddress.IPv4Network((int(ipaddress.IPv4Address("10.0.0.0")), prefix))

            self.hosts_vars["padded"].set(f"{padded}")
            self.hosts_vars["prefix"].set(f"/{prefix}")
            self.hosts_vars["mask"].set(str(mask))
            self.hosts_vars["total"].set(str(total))
            self.hosts_vars["usable"].set(str(usable))
            self.hosts_vars["example"].set(str(example_net))
        except Exception as e:
            messagebox.showerror("Input error", str(e))

    # ----------------------------
    # Tab 3: Practice mode 1
    # ----------------------------
    def _build_practice1_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Practice 1")

        info = ttk.Label(frame, text="Given a random IP/CIDR, solve: Network ID, First Host, Last Host, Broadcast, Next Network.")
        info.pack(fill=tk.X, padx=10, pady=10)

        qbox = ttk.LabelFrame(frame, text="Question")
        qbox.pack(fill=tk.X, padx=10, pady=10)
        ttk.Label(qbox, text="Target IP/CIDR:").grid(row=0, column=0, sticky="w", padx=6, pady=6)
        self.p1_q_var = tk.StringVar(value="")
        ttk.Entry(qbox, textvariable=self.p1_q_var, width=28, state="readonly").grid(row=0, column=1, sticky="w", padx=6, pady=6)
        self.p1_new_btn = ttk.Button(qbox, text="New question", command=self._p1_new_question)
        self.p1_new_btn.grid(row=0, column=2, padx=10, pady=6)

        abox = ttk.LabelFrame(frame, text="Your answers")
        abox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.p1_entries = {}
        fields = [
            ("Network ID:", "network"),
            ("First Host:", "first"),
            ("Last Host:", "last"),
            ("Broadcast:", "broadcast"),
            ("Next Network:", "nextnet"),
        ]
        for i, (label, key) in enumerate(fields):
            ttk.Label(abox, text=label).grid(row=i, column=0, sticky="w", padx=6, pady=6)
            e = ttk.Entry(abox, width=35)
            e.grid(row=i, column=1, sticky="w", padx=6, pady=6)
            self.p1_entries[key] = e

        btns = ttk.Frame(abox)
        btns.grid(row=len(fields), column=0, columnspan=2, sticky="w", padx=6, pady=6)
        ttk.Button(btns, text="Check answers", command=self._p1_check).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Show solution", command=self._p1_show_solution).pack(side=tk.LEFT, padx=6)
        self.p1_feedback = ttk.Label(abox, text="", foreground="blue")
        self.p1_feedback.grid(row=len(fields)+1, column=0, columnspan=2, sticky="w", padx=6, pady=6)

        self.p1_current = None
        self._p1_new_question()

    def _p1_new_question(self):
        iface = random_interface(min_prefix=20, max_prefix=30)
        self.p1_current = subnet_stats_from_interface(iface)
        self.p1_q_var.set(str(iface))
        self.p1_feedback.config(text="")
        for e in self.p1_entries.values():
            e.delete(0, tk.END)

    def _p1_check(self):
        if not self.p1_current:
            return
        stats = self.p1_current
        correct = {
            "network": str(stats["network_id"]),
            "first": str(stats["first_usable"]),
            "last": str(stats["last_usable"]),
            "broadcast": str(stats["broadcast"]),
            "nextnet": str(stats["next_network"]) if stats["next_network"] else "N/A",
        }
        wrong = []
        for key, entry in self.p1_entries.items():
            user = entry.get().strip()
            if user != correct[key]:
                wrong.append(f"{key}: expected {correct[key]}, got {user or '(blank)'}")
        if wrong:
            self.p1_feedback.config(text="Incorrect:\n- " + "\n- ".join(wrong), foreground="red")
        else:
            self.p1_feedback.config(text="All correct. Nice work.", foreground="green")

    def _p1_show_solution(self):
        if not self.p1_current:
            return
        stats = self.p1_current
        solutions = {
            "network": str(stats["network_id"]),
            "first": str(stats["first_usable"]),
            "last": str(stats["last_usable"]),
            "broadcast": str(stats["broadcast"]),
            "nextnet": str(stats["next_network"]) if stats["next_network"] else "N/A",
        }
        for key, entry in self.p1_entries.items():
            entry.delete(0, tk.END)
            entry.insert(0, solutions[key])
        self.p1_feedback.config(text="Solution filled.", foreground="blue")

    # ----------------------------
    # Tab 4: Practice mode 2 (DHCP-style gap fitting, alignment-aware, one correct answer)
    # ----------------------------
    def _build_practice2_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Practice 2")

        info = ttk.Label(
            frame,
            text="Allocated subnets are shown below (15–16 entries, sorted). "
                 "Your task: pick the ONE gap where the candidate CIDR size can fit, "
                 "respecting both space and subnet boundary alignment."
        )
        info.pack(fill=tk.X, padx=10, pady=10)

        upper = ttk.Frame(frame)
        upper.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        left = ttk.LabelFrame(upper, text="Allocated subnets (sorted)")
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6, pady=6)

        right = ttk.LabelFrame(upper, text="Candidate CIDR size")
        right.pack(side=tk.LEFT, fill=tk.Y, expand=False, padx=6, pady=6)

        self.p2_list = tk.Listbox(left, height=24, font=("Consolas", 11))
        self.p2_list.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.p2_scroll = ttk.Scrollbar(left, orient="vertical", command=self.p2_list.yview)
        self.p2_list.configure(yscrollcommand=self.p2_scroll.set)
        self.p2_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self.p2_candidate_var = tk.StringVar(value="")
        ttk.Entry(right, textvariable=self.p2_candidate_var, width=10, state="readonly").pack(padx=6, pady=6)

        btns = ttk.Frame(frame)
        btns.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(btns, text="New question", command=self._p2_new_question).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Check selection", command=self._p2_check).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Show solution", command=self._p2_show_solution).pack(side=tk.LEFT, padx=6)

        self.p2_feedback = ttk.Label(frame, text="", foreground="blue")
        self.p2_feedback.pack(fill=tk.X, padx=10, pady=6)

        # Internal state
        self.p2_allocations = []
        self.p2_candidate_prefix = None
        self.p2_correct_gap = None

        self._p2_new_question()

    def _generate_allocations_block(self, base="10.0.0.0/22", count=16):
        """Generate non-overlapping allocations inside a /22, with /24–/31 sizes."""
        base_net = ipaddress.IPv4Network(base)
        allocations = []
        attempts = 0
        while len(allocations) < count and attempts < 5000:
            pfx = random.randint(24, 31)
            candidates = list(base_net.subnets(new_prefix=pfx))
            cand = random.choice(candidates)
            if all(not cand.overlaps(a) for a in allocations):
                allocations.append(cand)
            attempts += 1
        allocations.sort(key=lambda n: int(n.network_address))
        return allocations, base_net

    def _gap_can_fit_aligned(self, gap_start, gap_end, prefix):
        """Check if a subnet of given prefix can fit in gap with proper alignment."""
        block_size = 2 ** (32 - prefix)
        # Find the first aligned start >= gap_start
        start = gap_start if gap_start % block_size == 0 else gap_start + (block_size - (gap_start % block_size))
        if start + block_size - 1 <= gap_end:
            return True
        return False

    def _p2_new_question(self):
        self.p2_list.delete(0, tk.END)
        self.p2_feedback.config(text="", foreground="blue")

        # Keep regenerating until we have exactly one valid gap
        for attempt in range(200):
            self.p2_allocations, base_net = self._generate_allocations_block(count=16)
            if not self.p2_allocations:
                continue

            self.p2_candidate_prefix = random.randint(24, 31)
            self.p2_candidate_var.set(f"/{self.p2_candidate_prefix}")

            valid_gaps = []

            # Populate listbox with allocations and gap markers
            self.p2_list.delete(0, tk.END)
            for i, net in enumerate(self.p2_allocations):
                self.p2_list.insert(tk.END, str(net))
                # Insert a gap marker after each allocation
                gap_start = int(net.broadcast_address) + 1
                gap_end = int(self.p2_allocations[i+1].network_address) - 1 if i < len(self.p2_allocations)-1 else int(base_net.broadcast_address)
                if gap_end >= gap_start:
                    gap_label = f"--- gap {i} ---"
                    self.p2_list.insert(tk.END, gap_label)
                    if self._gap_can_fit_aligned(gap_start, gap_end, self.p2_candidate_prefix):
                        valid_gaps.append(gap_label)

            if len(valid_gaps) == 1:
                self.p2_correct_gap = valid_gaps[0]
                return  # success

        self.p2_feedback.config(text="Failed to generate a valid question. Try again.", foreground="red")

    def _p2_check(self):
        sel = self.p2_list.curselection()
        if not sel:
            messagebox.showwarning("No selection", "Please select a gap from the list.")
            return
        idx = sel[0]
        text = self.p2_list.get(idx)
        if not text.startswith("--- gap"):
            self.p2_feedback.config(text="Please select a gap line, not an allocation.", foreground="red")
            return
        if text == self.p2_correct_gap:
            self.p2_feedback.config(text=f"Correct! A /{self.p2_candidate_prefix} fits in {text}.", foreground="green")
        else:
            self.p2_feedback.config(text=f"Incorrect. A /{self.p2_candidate_prefix} does not fit in {text}.", foreground="red")

    def _p2_show_solution(self):
        if not self.p2_correct_gap:
            return
        self.p2_list.selection_clear(0, tk.END)
        for i in range(self.p2_list.size()):
            text = self.p2_list.get(i)
            if text == self.p2_correct_gap:
                self.p2_list.selection_set(i)
                self.p2_list.see(i)
                self.p2_feedback.config(
                    text=f"Solution: A /{self.p2_candidate_prefix} fits only in {self.p2_correct_gap}.",
                    foreground="blue"
                )
                break

# ----------------------------
# Main
# ----------------------------

if __name__ == "__main__":
    app = SubnetApp()
    app.mainloop()
