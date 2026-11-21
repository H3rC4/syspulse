app-title = SysPulse

# Tabs
tab-process-hunter = Process Hunter
tab-cleaner = Cleaner
tab-cpu-focus = CPU Focus
tab-settings = Settings

# Common
btn-ok = OK
btn-cancel = Cancel
btn-save = Save
btn-scan = Scan
btn-clean = Clean
btn-restore = Restore
btn-delete = Delete
btn-focus = Focus
btn-unfocus = Unfocus
btn-export = Export
status-loading = Loading...
status-ready = Ready

# Process Hunter
process-hunter-title = Process Hunter
process-hunter-description = Monitor process creation and detect transient processes.
process-hunter-paused = Monitoring paused
process-hunter-running = Monitoring active
process-hunter-column-time = Time
process-hunter-column-name = Name
process-hunter-column-pid = PID
process-hunter-column-parent = Parent
process-hunter-column-lifetime = Lifetime
process-hunter-transient = Transient
process-hunter-export-hint = Select a process and export it to analyze with your AI.

# Cleaner
cleaner-title = Smart Cleaner
cleaner-description = Clean temporary files, developer caches, and find duplicate files.
cleaner-tab-system = System Sweep
cleaner-tab-duplicates = Duplicate Finder
cleaner-tab-quarantine = Quarantine
cleaner-files-found = Files found: { $count }
cleaner-bytes-reclaimable = Reclaimable: { $size }
cleaner-scanning = Scanning...
cleaner-cleaning = Cleaning...
cleaner-no-duplicates = No duplicates found.
cleaner-select-folder = Select folder
cleaner-smart-select = Smart Select
cleaner-quarantine-days = Quarantine retention: { $days } days (auto-purge temporarily suspended)

# CPU Focus
cpu-focus-title = CPU Focus
cpu-focus-description = Select a process to raise its priority and improve responsiveness.
cpu-focus-column-name = Process
cpu-focus-column-cpu = CPU %
cpu-focus-column-memory = Memory
cpu-focus-elevated = Elevated privileges active
cpu-focus-elevation-needed = Elevated privileges required for this action.

# Settings
settings-title = Settings
settings-description = Configure language, theme, and system preferences.
settings-language = Language
settings-theme = Theme
settings-dark-mode = Dark mode
settings-start-with-os = Start with operating system
settings-history-days = Process history retention (days)
settings-quarantine-days = Quarantine retention (days) (auto-purge suspended)
settings-check-updates = Check for updates
settings-version = Version { $version }

# Tray
tray-open = Open SysPulse
tray-pause = Pause monitoring
tray-resume = Resume monitoring
tray-exit = Exit

# Errors
error-elevation-denied = Elevation was denied. Some features will be disabled.
error-generic = An error occurred: { $message }

# System Monitor
tab-monitor = Monitor
monitor-title = System Monitor
monitor-description = Real-time system performance metrics
monitor-cpu = CPU
monitor-ram = Memory
monitor-swap = Swap
monitor-disks = Disks
monitor-network = Network
monitor-network-upload = Upload
monitor-network-download = Download
monitor-temps = Temperatures
monitor-no-sensors = No sensors detected
monitor-system-info = System Info
monitor-uptime = Uptime
monitor-load-avg = Load Average
monitor-top-cpu = Top 5 by CPU
monitor-top-ram = Top 5 by Memory

# Network Guardian
tab-network-guardian = Network Guardian
net-guardian-title = Network Guardian
net-guardian-description = Local network inventory, Wi-Fi channel diagnostics, and real-time link quality.
net-tab-devices = Devices
net-tab-wifi = Wi-Fi Analyzer
net-tab-link = Link Quality
net-device-this-pc = This PC
net-device-gateway = Router / Gateway
net-device-vendor = { $vendor } Device
net-device-laa = LAA Address (Virtual / Private)
net-device-unknown = Unknown Device
net-device-trusted = Trusted
net-device-untrusted = Unknown
net-scan-running = Scanning network...
net-scan-partial = Partial scan bounded to { $count } hosts
net-devices-empty = No devices found in local network cache. Click Refresh to inspect ARP table.
net-wifi-unavailable = Wi-Fi adapter disconnected or unavailable (Ethernet in use).
net-link-gateway = Gateway Latency
net-link-internet = Internet Latency
net-link-jitter = Jitter
net-link-loss = Packet Loss

# Pulse Intelligence Engine (PIE)
tab-pie-incidents = Incident Center
pie-title = Intelligence & Incident Center
pie-description = Correlated security and performance diagnostics across system, network, and processes.
pie-incidents-empty = No incidents recorded. All systems operating within normal parameters.
pie-evidences-title = Observable Evidences
pie-filter-all = All
pie-filter-active = Active
pie-filter-resolved = Resolved
pie-rule-wifi-deg-title = Unstable or Weak Wi-Fi Signal
pie-rule-ext-down-title = Local Connection Active but No Internet Access
pie-rule-rogue-gw-title = Unexpected Gateway or Topology Change
pie-rule-ip-conflict-title = Two Devices Sharing the Same Local IP Address
pie-rule-high-cpu-title = An Application is Overloading the Processor
pie-rule-mem-pressure-title = System Physical Memory is Nearly Full
pie-rule-sys-saturation-title = System Operating at Hardware Limits
pie-rule-temp-exec-title = Unverified Application Executing from Temp Directory

