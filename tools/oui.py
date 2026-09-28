"""Base OUI offline: prefijos MAC comunes (sin internet)."""
DB = {
    # Apple
    "ac:de:48": "Apple", "f0:18:98": "Apple", "a4:5e:60": "Apple",
    "8c:85:90": "Apple", "d0:23:db": "Apple", "e0:ac:cb": "Apple",
    # Samsung
    "8c:f5:a3": "Samsung", "9c:c7:a8": "Samsung", "e4:7b:34": "Samsung",
    "c0:bd:d4": "Samsung",
    # Xiaomi / Redmi
    "64:cc:2e": "Xiaomi", "78:11:dc": "Xiaomi", "7c:2f:80": "Xiaomi",
    # Huawei
    "e8:cd:2d": "Huawei", "48:d5:39": "Huawei", "04:02:1f": "Huawei",
    # PCs
    "b8:ca:3a": "Dell", "f8:ca:b8": "Dell", "18:66:da": "Dell",
    "3c:d9:2b": "HP", "70:5a:0f": "HP", "a0:d3:7a": "HP",
    "8c:16:45": "Lenovo", "54:ee:75": "Lenovo", "f0:76:1c": "Lenovo",
    "9c:eb:e8": "Asus", "2c:56:dc": "Asus", "04:d4:c4": "Asus",
    "00:1e:67": "Acer", "b0:7f:b9": "Acer",
    # Chips de red
    "b4:2e:99": "Intel", "34:e6:ad": "Intel", "a0:af:bd": "Intel",
    "00:e0:4c": "Realtek", "52:54:00": "QEMU/KVM virtual", "00:15:5d": "Hyper-V virtual",
    "00:50:56": "VMware virtual", "00:0c:29": "VMware virtual", "08:00:27": "VirtualBox",
    # Routers / IoT
    "50:c7:bf": "TP-Link", "84:d8:1b": "TP-Link", "f4:ec:38": "TP-Link",
    "30:b5:c2": "TP-Link", "14:cc:20": "TP-Link",
    "44:fe:3b": "Tenda", "c8:3a:35": "Tenda",
    "78:44:fd": "Mercusys",
    "18:e8:29": "Nintendo", "cc:fb:65": "Nintendo",
    "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi", "b8:27:eb": "Raspberry Pi",
    "d8:a0:1d": "Amazon (Echo/Fire)", "44:65:0d": "Amazon",
    "18:b4:30": "Google (Nest/Chromecast)", "f4:f5:d8": "Google",
    "28:6d:cd": "Sonos", "78:28:ca": "Sonos",
    "50:dc:e7": "Xiaomi (IoT)", "54:48:e6": "Huawei (IoT)",
    # Móviles extra
    "a0:cc:2b": "LG", "e0:1c:41": "LG",
    "60:f1:89": "Motorola", "04:c2:3e": "Motorola",
    "9c:2f:9d": "OnePlus", "f4:09:d8": "OnePlus",
    "ac:83:f3": "Oppo", "e8:d0:3c": "Oppo",
    "5c:49:7d": "Vivo", "78:8b:08": "Vivo",
    "28:16:a8": "Realme",
    "00:23:76": "Nokia", "c0:8b:96": "Nokia",
    "00:1d:b5": "ZTE", "34:4d:ea": "ZTE",
    # Red hogar
    "00:26:f2": "Netgear", "9c:3d:cf": "Netgear", "e8:fc:af": "Netgear",
    "00:1c:f0": "D-Link", "1c:7e:e5": "D-Link", "c4:3d:c7": "D-Link",
    "00:1d:aa": "Arris", "e4:5d:51": "Arris",
    "a8:5e:45": "Asus (router)", "ac:22:0b": "Asus (router)",
    "70:4f:57": "Roku", "b8:13:32": "Roku",
    "00:17:88": "Philips Hue", "ec:b5:fa": "Philips Hue",
    "fc:a1:83": "LG (TV)", "7c:2e:bd": "Samsung (TV)",
}
