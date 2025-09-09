import tkinter as tk
from tkinter import ttk
import threading
import ctypes
from ctypes import wintypes
import getpass
import time
import tkinter.font as tkFont

# ------- Windows API Setup -------- #
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
user32 = ctypes.WinDLL('user32', use_last_error=True)

TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

PROCESS_QUERY_INFORMATION = 0x0400
TOKEN_QUERY = 0x0008
TokenUser = 1

# ------ Freeze/Unfreeze Constants & functions ------- #
THREAD_SUSPEND_RESUME = 0x0002
THREAD_QUERY_INFORMATION = 0x0040

# ------- Window manipulation functions ---- #
SW_MINIMIZE = 6
SW_RESTORE = 9

# Load kernel32 functions
OpenThread = kernel32.OpenThread
SuspendThread = kernel32.SuspendThread
ResumeThread = kernel32.ResumeThread
CloseHandle = kernel32.CloseHandle
CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
Thread32First = kernel32.Thread32First
Thread32Next = kernel32.Thread32Next

# Thread structure
class THREADENTRY32(ctypes.Structure):
	_fields_ = [
		("dwSize", ctypes.c_uint32),
		("cntUsage", ctypes.c_uint32),
		("th32ThreadID", ctypes.c_uint32),
		("th32OwnerProcessID", ctypes.c_uint32),
		("tpBasePri", ctypes.c_long),
		("tpDeltaPri", ctypes.c_long),
		("dwFlags", ctypes.c_uint32)
	]

def suspend_process(pid):
	"""Suspend all threads of a process"""
	hSnapshot = CreateToolhelp32Snapshot(0x00000004, 0)
	if hSnapshot == INVALID_HANDLE_VALUE:
		return False

	te32 = THREADENTRY32()
	te32.dwSize = ctypes.sizeof(THREADENTRY32)

	if Thread32First(hSnapshot, ctypes.byref(te32)):
		while True:
			if te32.th32OwnerProcessID == pid:
				hThread = OpenThread(THREAD_SUSPEND_RESUME, False, te32.th32ThreadID)
				if hThread:
					SuspendThread(hThread)
					CloseHandle(hThread)

			if not Thread32Next(hSnapshot, ctypes.byref(te32)):
				break

	CloseHandle(hSnapshot)
	return True

def resume_process(pid):
	"""Resume all threads of a process"""
	hSnapshot = CreateToolhelp32Snapshot(0x00000004, 0)
	if hSnapshot == INVALID_HANDLE_VALUE:
		return False

	te32 = THREADENTRY32()
	te32.dwSize = ctypes.sizeof(THREADENTRY32)

	if Thread32First(hSnapshot, ctypes.byref(te32)):
		while True:
			if te32.th32OwnerProcessID == pid:
				hThread = OpenThread(THREAD_SUSPEND_RESUME, False, te32.th32ThreadID)
				if hThread:
					ResumeThread(hThread)
					CloseHandle(hThread)

			if not Thread32Next(hSnapshot, ctypes.byref(te32)):
				break

	CloseHandle(hSnapshot)
	return True

# Structures
class PROCESSENTRY32(ctypes.Structure):
	_fields_ = [
		("dwSize", ctypes.c_uint32),
		("cntUsage", ctypes.c_uint32),
		("th32ProcessID", ctypes.c_uint32),
		("th32DefaultHeapID", ctypes.c_void_p),
		("th32ModuleID", ctypes.c_uint32),
		("cntThreads", ctypes.c_uint32),
		("th32ParentProcessID", ctypes.c_uint32),
		("pcPriClassBase", ctypes.c_long),
		("dwFlags", ctypes.c_uint32),
		("szExeFile", ctypes.c_char * 260),
	]

class SID_AND_ATTRIBUTES(ctypes.Structure):
	_fields_ = [
		("Sid", ctypes.POINTER(ctypes.c_byte)),
		("Attributes", wintypes.DWORD)
	]


class TOKEN_USER(ctypes.Structure):
	_fields_ = [("User", SID_AND_ATTRIBUTES)]

# ---- Functions ---- #
def get_process_username(pid):
	"""Return username of process owner for given PID or None if not accessible"""
	hProcess = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
	if not hProcess:
		return None

	hToken = wintypes.HANDLE()
	if not advapi32.OpenProcessToken(hProcess, TOKEN_QUERY, ctypes.byref(hToken)):
		kernel32.CloseHandle(hProcess)
		return None

	length = wintypes.DWORD()
	advapi32.GetTokenInformation(hToken, TokenUser, None, 0, ctypes.byref(length))

	buf = ctypes.create_string_buffer(length.value)
	if not advapi32.GetTokenInformation(hToken, TokenUser, buf, length, ctypes.byref(length)):
		kernel32.CloseHandle(hToken)
		kernel32.CloseHandle(hProcess)
		return None

	token_user = ctypes.cast(buf, ctypes.POINTER(TOKEN_USER)).contents

	name_size = wintypes.DWORD(0)
	domain_size = wintypes.DWORD(0)
	advapi32.LookupAccountSidW(None, token_user.User.Sid, None, ctypes.byref(name_size), None, ctypes.byref(domain_size), None)

	name = ctypes.create_unicode_buffer(name_size.value)
	domain = ctypes.create_unicode_buffer(domain_size.value)
	sid_name_use = wintypes.DWORD()
	if advapi32.LookupAccountSidW(None, token_user.User.Sid, name, ctypes.byref(name_size), domain, ctypes.byref(domain_size), ctypes.byref(sid_name_use)):
		username = f"{domain.value}\\{name.value}"
	else:
		username = None

	kernel32.CloseHandle(hToken)
	kernel32.CloseHandle(hProcess)
	return username


def get_running_process_user_filtered_tree():
	"""Return processes owned by current user, structured for parent-child mapping"""
	current_user = getpass.getuser()
	all_procs = {} # pid -> (name, parent pid)

	hSnapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if hSnapshot == INVALID_HANDLE_VALUE:
		return {}, {}

	pe32 = PROCESSENTRY32()
	pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

	if kernel32.Process32First(hSnapshot, ctypes.byref(pe32)):
		while True:
			pid = pe32.th32ProcessID
			name = pe32.szExeFile.decode(errors="ignore")
			ppid = pe32.th32ParentProcessID
			owner = get_process_username(pid)

			if owner and owner.endswith(current_user):
				all_procs[pid] = (name, ppid)
			if not kernel32.Process32Next(hSnapshot, ctypes.byref(pe32)):
				break
	kernel32.CloseHandle(hSnapshot)

	# Build parent -> children mapping
	parent_map = {}
	for pid, (name, ppid) in all_procs.items():
		parent_map.setdefault(ppid, []).append(pid)

	return all_procs, parent_map

EnumWindows = user32.EnumWindows
EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
GetWindowThreadProcessId = user32.GetWindowThreadProcessId
IsWindowVisible = user32.IsWindowVisible
ShowWindow = user32.ShowWindow

def get_hwnd_for_pid(pid):
	"""Get the window handles for a process"""
	hwnds = []

	def foreach_window(hwnd, IParam):
		if IsWindowVisible(hwnd):
			p = wintypes.DWORD()
			GetWindowThreadProcessId(hwnd, ctypes.byref(p))
			if p.value == pid:
				hwnds.append(hwnd)

		return True

	EnumWindows(EnumWindowsProc(foreach_window), 0)

	return hwnds if hwnds else None

def minimize_all_windows_by_name(process_name):
	all_procs, _ = get_running_process_user_filtered_tree()
	for pid, (name, _) in all_procs.items():
		if name.lower() == process_name.lower():
			hwnds = get_hwnd_for_pid(pid)
			if hwnds:
				for hwnd in hwnds:
					ShowWindow(hwnd, SW_MINIMIZE)

def restore_all_windows_by_name(process_name):
	all_procs, _ = get_running_process_user_filtered_tree()
	for pid, (name, _) in all_procs.items():
		if name.lower() == process_name.lower():
			hwnds = get_hwnd_for_pid(pid)
			if hwnds:
				for hwnd in hwnds:
					ShowWindow(hwnd, SW_RESTORE)


#------ TKINTER GUI ------ #
root = tk.Tk()
root.title("User Processes Viewer")
root.geometry("800x600")

# ---- Style for Treeview padding ---- #
style = ttk.Style()
style.configure("Treeview", rowheight=20) # New row padding

# ---- Larger font for better spacing ---- #
tree_font = tkFont.Font(family="Segoe UI", size=11)

tree_frame = tk.Frame(root, padx=10, pady=10)
tree_frame.pack(fill=tk.BOTH, expand=True)

# ----- Search Bar ----- #
search_frame = tk.Frame(root)
search_frame.pack(pady=5)

tk.Label(search_frame, text="Search Process:").pack(side=tk.LEFT, padx=5)

search_var = tk.StringVar()
search_entry = tk.Entry(search_frame, textvariable=search_var)
search_entry.pack(side=tk.LEFT, padx=5)

# Search + Next/Prev navigation
search_results = []
current_search_index = -1

def search_process():
	global search_results, current_search_index
	query = search_var.get().lower().strip()
	search_results = []

	for item in tree.get_children():
		name = tree.item(item)['values'][0].lower()
		if query in name:
			search_results.append(item)

	if search_results:
		current_search_index = 0
		tree.selection_set(search_results[0])
		tree.see(search_results[0])

def find_next():
	global current_search_index
	if not search_results:
		return

	current_search_index = (current_search_index + 1) % len(search_results)
	item = search_results[current_search_index]
	tree.selection_set(item)
	tree.see(item)

def find_prev():
	global current_search_index
	if not search_results:
		return

	current_search_index = (current_search_index - 1) % len(search_results)
	item = search_results[current_search_index]
	tree.selection_set(item)
	tree.see(item)

tk.Button(search_frame, text="Search", command=search_process).pack(side=tk.LEFT, padx=5)
tk.Button(search_frame, text="Find Next", command=find_next).pack(side=tk.LEFT, padx=5)
tk.Button(search_frame, text="Find Prev", command=find_prev).pack(side=tk.LEFT, padx=5)

search_entry.bind("<Return>", lambda event: search_process())

columns = ("Process Name",)
tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
tree.heading("Process Name", text="Process Name")
tree.column("Process Name", width=250, anchor="w")

# ---- Apply font to tree ---- #
style.configure("Treeview", font=tree_font)

tree.pack(fill=tk.BOTH, expand=True)

# Keep track of PID -> item_id mapping
pid_to_item = {}

def refresh_tree():
	"""Diff-update the tree without flickering"""
	global pid_to_item
	all_procs, parent_map = get_running_process_user_filtered_tree()
	current_pids = set(all_procs.keys())
	existing_pids = set(pid_to_item.keys())

	# 1. Add new processes
	for pid in current_pids - existing_pids:
		name, ppid = all_procs[pid]
		parent_item = pid_to_item.get(ppid, "")
		item = tree.insert(parent_item, "end", text=name, values=(name, pid))
		pid_to_item[pid] = item

	# 2. Remove dead processes
	# for pid in existing_pids - current_pids:
	# 	item_id = pid_to_item.pop(pid, None)
	# 	if item_id:
	# 		tree.delete(item_id)

	# 3. Update existing processes
	for pid in current_pids & existing_pids:
		name, _ = all_procs[pid]
		tree.item(pid_to_item[pid], text=name, values=(name, pid))

	# Schedule next refresh
	tree.after(2000, refresh_tree)

# Start dynamic tree refresh
refresh_tree()


def freeze_selected():
	selected = tree.selection()
	if selected:
		# pid = tree.item(selected[0])['values'][1]
		name = tree.item(selected[0])['values'][0]

		# minimize all windows for this app
		minimize_all_windows_by_name(name)

		# freeze all PIDs that match this name
		all_procs, _ = get_running_process_user_filtered_tree()
		for pid, (proc_name, _) in all_procs.items():
			if proc_name.lower() == name.lower():
				suspend_process(pid)

def unfreeze_selected():
	selected = tree.selection()
	if selected:
		# pid = tree.item(selected[0])['values'][1]
		name = tree.item(selected[0])['values'][0]

		# restore all processes with this name
		all_procs, _ = get_running_process_user_filtered_tree()
		for pid, (proc_name, _) in all_procs.items():
			if proc_name.lower() == name.lower():
				resume_process(pid)
		
		# restore all windows for this app
		restore_all_windows_by_name(name)

btn_frame = tk.Frame(root)
btn_frame.pack(pady=5)

tk.Button(btn_frame, text="Freeze", command=freeze_selected).pack(side=tk.LEFT, padx=5)
tk.Button(btn_frame, text="Unfreeze", command=unfreeze_selected).pack(side=tk.LEFT, padx=5)

root.mainloop()
