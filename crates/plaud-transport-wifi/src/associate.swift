import Foundation
import CoreWLAN
struct Request: Decodable { let interface:String; let ssid:String; let password:String? }
do {
    let request=try JSONDecoder().decode(Request.self,from:FileHandle.standardInput.readDataToEndOfFile())
    guard let interface=CWWiFiClient.shared().interface(withName:request.interface) else { exit(2) }
    let networks=try interface.scanForNetworks(withSSID:request.ssid.data(using:.utf8))
    guard let network=networks.first(where: { $0.ssid == request.ssid }) else { exit(3) }
    try interface.associate(to:network,password:request.password)
    print("associated")
} catch { exit(4) }
