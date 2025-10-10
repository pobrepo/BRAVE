metadata {
    definition(name: "HomeKit Driver (user)", namespace: "custom", author: "you") {
        capability "GarageDoorControl"
        capability "ContactSensor"
        capability "Actuator"
        capability "Sensor"
        capability "Refresh"
        capability "Switch"

        attribute "door", "ENUM", ["open","closed","opening","closing"]
        attribute "contact", "ENUM", ["open","closed"]
        command "syncState", ["STRING"]
        command "bleAction", ["STRING"]
    }
}

preferences {
    input name: "lockoutStart", type: "number", title: "Lockout Start (24h)", defaultValue: 0, required: true
    input name: "lockoutEnd", type: "number", title: "Lockout End (24h)", defaultValue: 0, required: true
    input name: "blockBluetoothOnly", type: "bool", title: "Block Bluetooth Only", defaultValue: false
    input name: "blockAll", type: "bool", title: "Block All (HomeKit, etc.)", defaultValue: false
    input name: "minFlipMs", type: "number", title: "Min ms between state changes", defaultValue: 750, required: true
    input name: "minPulseMs", type: "number", title: "Min ms between actuator pulses", defaultValue: 750, required: true
    input name: "enableDebug", type: "bool", title: "Enable debug logging", defaultValue: true
    input name: "enableInfo", type: "bool", title: "Enable info logging", defaultValue: true
}

def installed() { updated() }
def updated() { info "GAR Driver updated" }

def refresh() {
    info "refresh()"
    def s = (device.currentValue("door") ?: "closed")
    sendEvent(name: "door", value: s, isStateChange: false)
    sendEvent(name: "contact", value: s, isStateChange: false)
}

private long nowMs(){ return now() as long }
private long flipMs(){ def v=settings?.minFlipMs; return (v instanceof Number)? (v as long):1500L }
private long pulseMs(){ def v=settings?.minPulseMs; return (v instanceof Number)? (v as long):1500L }
private boolean tooSoon(ts, long limitMs){ long last=(ts?:0L) as long; return (nowMs()-last) < limitMs }

def syncState(v) {
    debug "syncState(${v})"
    def s = (v?.toString()?.toLowerCase() == "open") ? "open" : "closed"
    if (device.currentValue("door") == s && device.currentValue("contact") == s) return
    if (tooSoon(state.lastDoorChangeMs, flipMs())) { debug "DEBOUNCE syncState ${s}"; return }
    state.lastDoorChangeMs = nowMs()
    sendEvent(name: "door", value: s)
    sendEvent(name: "contact", value: s)
}

def bleAction(v) {
    def id = getDoorDeviceId(); if (id == null) return
    if (isLockoutTime() && blockBLE) { warn "LOCKOUT BLE: ${v} ${id}"; return }

    def raw = v?.toString() ?: ""
    def parts = raw.split(/\|/, 2)
    def t = (parts[0] ?: "open").toLowerCase()
    def meta = (parts.size() > 1) ? java.net.URLDecoder.decode(parts[1], "UTF-8") : null
    if (meta) debug "BLE META ${meta}"

    info "BLE: ${t} ${id}"
    sendEvent(name: "door", value: (t == "close" ? "closing" : "opening"))
    pulseDoor(id, "Door")
}

def open() {
    def id = getDoorDeviceId(); if (id == null) return
    if (device.currentValue("door") == "open") { info "HOMEKIT: Open ${id} - Already open"; return }
    if (isLockoutTime() && blockAll) { warn "LOCKOUT: Open ${id}"; return }
    if (tooSoon(state.lastPulseMs, pulseMs())) { debug "DEBOUNCE pulse (open)"; return }
    state.lastPulseMs = nowMs()
    info "HOMEKIT: Open ${id}"
    sendEvent(name: "door", value: "opening")
    pulseDoor(id, "Door")
}

def close() {
    def id = getDoorDeviceId(); if (id == null) return
    if (device.currentValue("door") == "closed") { info "HOMEKIT: Close ${id} - Already closed"; return }
    if (isLockoutTime() && blockAll) { warn "LOCKOUT: Close ${id}"; return }
    if (tooSoon(state.lastPulseMs, pulseMs())) { debug "DEBOUNCE pulse (close)"; return }
    state.lastPulseMs = nowMs()
    info "HOMEKIT: Close ${id}"
    sendEvent(name: "door", value: "closing")
    pulseDoor(id, "Door")
}

private pulseDoor(id, label) {
    def onUrl = "http://192.168.1.200:8080/apps/api/80/devices/${id}/on?access_token=ab1c91a0-1e3b-4eea-83fd-2c04923eaf67"
    httpGet([uri: onUrl, timeout: 5]) { resp ->
        pauseExecution(500)
        def offUrl = "http://192.168.1.200:8080/apps/api/80/devices/${id}/off?access_token=ab1c91a0-1e3b-4eea-83fd-2c04923eaf67"
        httpGet([uri: offUrl, timeout: 5]) { resp2 ->
            info "PULSED: ${label} > (${id})"
        }
    }
}

private getDoorDeviceId() {
    def devId = device?.id as String
    def relay = null
    if (devId == "204") relay = 116
    else if (devId == "205") relay = 117
    else if (devId == "206") relay = 118
    if (relay != null) { debug "MAP device.id=${devId} -> relay ${relay}"; return relay }
    warn "UNKNOWN DEVICE ID: ${devId}"
    return null
}

private isLockoutTime() {
    def now = new Date()
    def h = now.format('HH', location.timeZone).toInteger()
    if (lockoutStart <= lockoutEnd) { return h >= lockoutStart && h < lockoutEnd }
    else { return h >= lockoutStart || h < lockoutEnd }
}

def parse(String description) { debug "parse() called with description: ${description}" }

private debug(msg){ if (enableDebug) log.debug new Date().format('HH:mm:ss') + " " + msg }
private info(msg){  if (enableInfo)  log.info  new Date().format('HH:mm:ss') + " " + msg }
private warn(msg){  log.warn new Date().format('HH:mm:ss') + " " + msg }