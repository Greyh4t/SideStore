//
//  Keychain.swift
//  AltStore
//
//  Created by Riley Testut on 6/4/19.
//  Copyright © 2019 Riley Testut. All rights reserved.
//

import Foundation
import Security
private import KeychainAccess
@preconcurrency import AltSign

@_silgen_name("SecTaskCreateFromSelf")
private func SecTaskCreateFromSelf(_ allocator: CFAllocator?) -> CFTypeRef

@_silgen_name("SecTaskCopyValueForEntitlement")
private func SecTaskCopyValueForEntitlement(
    _ task: CFTypeRef,
    _ entitlement: CFString,
    _ error: UnsafeMutablePointer<Unmanaged<CFError>?>?
) -> Unmanaged<CFTypeRef>?

@propertyWrapper
public struct KeychainItem<Value>
{
    public let key: String
    
    public var wrappedValue: Value? {
        get {
            switch Value.self
            {
            case is Data.Type: return Keychain.shared.data(forKey: self.key) as? Value
            case is String.Type: return Keychain.shared.string(forKey: self.key) as? Value
            default: return nil
            }
        }
        set {
            switch Value.self
            {
            case is Data.Type: Keychain.shared.setData(newValue as? Data, forKey: self.key)
            case is String.Type: Keychain.shared.setString(newValue as? String, forKey: self.key)
            default: break
            }
        }
    }
    
    public init(key: String)
    {
        self.key = key
    }
}

public class Keychain
{
    public static let shared = Keychain()

    private let legacyKeychain: KeychainAccess.Keychain
    fileprivate let keychain: KeychainAccess.Keychain

    private static let allKeys = [
        "appleIDEmailAddress", "appleIDPassword", "appleIDAdsid", "appleIDXcodeToken",
        "signingCertificate", "signingCertificatePassword", "signingCertificatePrivateKey",
        "signingCertificateSerialNumber", "identifier", "adiPb"
    ]
    
    @KeychainItem(key: "appleIDEmailAddress")
    public var appleIDEmailAddress: String?
    
    @KeychainItem(key: "appleIDPassword")
    public var appleIDPassword: String?
    
    @KeychainItem(key: "appleIDAdsid")
    public var appleIDAdsid: String?
    
    @KeychainItem(key: "appleIDXcodeToken")
    public var appleIDXcodeToken: String?
    
    @KeychainItem(key: "signingCertificate")
    public var signingCertificate: Data?
    
    @KeychainItem(key: "signingCertificatePassword")
    public var signingCertificatePassword: String?
    
    // TODO: mahee96: remove legacy keys in later versions after 0.6.4 coz by now our migrations should be effectively moved all
    // Legacy
    @KeychainItem(key: "signingCertificatePrivateKey")
    public var signingCertificatePrivateKey: Data?
    
    // TODO: mahee96: remove legacy keys in later versions after 0.6.4 coz by now our migrations should be effectively moved all
    // Legacy
    @KeychainItem(key: "signingCertificateSerialNumber")
    public var signingCertificateSerialNumber: String?
    
    @KeychainItem(key: "identifier")
    public var identifier: String?
    
    @KeychainItem(key: "adiPb")
    public var adiPb: String?

    // MARK: - Dynamic Imported Certificates Storage

    public subscript(certificateSerial serial: String) -> Data? {
        get { self.data(forKey: "importedCert_" + serial) }
        set { self.setData(newValue, forKey: "importedCert_" + serial) }
    }
    
    private init() {
        let service = Bundle.Info.appbundleIdentifier
        self.legacyKeychain = KeychainAccess.Keychain(service: service)
            .accessibility(.afterFirstUnlock)
            .synchronizable(true)

        if let accessGroup = Self.liveContainerSharedAccessGroup() {
            self.keychain = KeychainAccess.Keychain(service: service, accessGroup: accessGroup)
                .accessibility(.afterFirstUnlock)
                .synchronizable(true)
            self.migrateItemsToSharedKeychain(accessGroup: accessGroup)
        } else {
            self.keychain = self.legacyKeychain
        }

        self.migrateLegacyKeychainItems()
    }

    private static func liveContainerSharedAccessGroup() -> String? {
        let task = SecTaskCreateFromSelf(nil)
        guard let value = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil)?.takeRetainedValue(),
              let groups = value as? [String]
        else {
            return nil
        }
        return groups.first { $0.hasSuffix(".com.kdt.livecontainer.shared") }
    }

    private func migrateItemsToSharedKeychain(accessGroup: String) {
        var migratedKeys: [String] = []
        for key in Self.allKeys where (try? self.keychain.getData(key)) == nil && (try? self.keychain.getString(key)) == nil {
            if let data = try? self.legacyKeychain.getData(key) {
                try? self.keychain.set(data, key: key)
                migratedKeys.append(key)
            } else if let string = try? self.legacyKeychain.getString(key) {
                try? self.keychain.set(string, key: key)
                migratedKeys.append(key)
            }
        }
        debugLog("[Keychain] LiveContainer shared access group enabled: \(accessGroup), migratedKeyCount=\(migratedKeys.count)")
    }

    fileprivate func data(forKey key: String) -> Data? {
        if let value = try? self.keychain.getData(key) {
            return value
        }
        guard let value = try? self.legacyKeychain.getData(key) else { return nil }
        try? self.keychain.set(value, key: key)
        return value
    }

    fileprivate func string(forKey key: String) -> String? {
        if let value = try? self.keychain.getString(key) {
            return value
        }
        guard let value = try? self.legacyKeychain.getString(key) else { return nil }
        try? self.keychain.set(value, key: key)
        return value
    }

    fileprivate func setData(_ value: Data?, forKey key: String) {
        self.keychain[data: key] = value
        if value == nil && self.keychain !== self.legacyKeychain {
            self.legacyKeychain[data: key] = nil
        }
    }

    fileprivate func setString(_ value: String?, forKey key: String) {
        self.keychain[key] = value
        if value == nil && self.keychain !== self.legacyKeychain {
            self.legacyKeychain[key] = nil
        }
    }
    
    private func migrateLegacyKeychainItems()
    {
        let signingCertificateKey   = "signingCertificate"
        let privateKeyKey           = "signingCertificatePrivateKey"
        let serialNumberKey         = "signingCertificateSerialNumber"
        
        // 1. Check if signingCertificate contains data and is NOT a PKCS#12 archive
        guard let certData = try? self.keychain.getData(signingCertificateKey), !certData.isPKCS12 else { return }
        
        // 2. Check if we have the private key
        guard let privateKey = try? self.keychain.getData(privateKeyKey) else { return }
        
        // 3. Load the raw certificate and pair with private key
        guard let x509 = ALTX509Certificate(data: certData) else { return }
        let cert = ALTCertificate(x509: x509, privateKey: privateKey)
        
        // 4. Create PKCS12 data structure
        do {
            let p12Data = try cert.unencryptedP12Data()
            // 5. Store the new PKCS12 format in signingCertificate slot
            try self.keychain.set(p12Data, key: signingCertificateKey)
            try self.keychain.set("", key: "signingCertificatePassword")
            
            // 6. Clear legacy keys
            try self.keychain.remove(privateKeyKey)
            try self.keychain.remove(serialNumberKey)
            
            debugLog("[Keychain] Successfully migrated legacy certificate and private key to PKCS12 format and cleared legacy keys.")
        } catch {
            debugLog("[Keychain] Failed to migrate legacy certificate to PKCS12 format: \(error)")
        }
    }
    
    public func reset(keepCertificate: Bool = false, keepAnisetteData: Bool = true)
    {
        debugLog("[Keychain] Resetting Keychain items (keepCertificate: \(keepCertificate), keepAnisetteData: \(keepAnisetteData))...")
        
        self.appleIDEmailAddress = nil
        self.appleIDPassword = nil
        self.appleIDAdsid = nil
        self.appleIDXcodeToken = nil
        debugLog("[Keychain] Cleared Apple ID credentials & tokens (email, password, adsid, xcodeToken).")
        
        if !keepCertificate {
            // Legacy
            self.signingCertificatePrivateKey = nil
            self.signingCertificateSerialNumber = nil

            self.signingCertificate = nil
            self.signingCertificatePassword = nil
            debugLog("[Keychain] Cleared signing certificate & private key.")
        } else {
            debugLog("[Keychain] Preserved signing certificate.")
        }
        
        if !keepAnisetteData {
            self.adiPb = nil
            debugLog("[Keychain] Cleared Anisette ADI data (adiPb).")
        } else {
            debugLog("[Keychain] Preserved Anisette ADI data (adiPb).")
        }
        
        debugLog("[Keychain] Cleared in-memory session, certificate, and team instances.")
    }

    public func clearAll()
    {
        debugLog("[Keychain] Clearing all Keychain items related to this instance...")
        try? self.keychain.removeAll()
        if self.keychain !== self.legacyKeychain {
            try? self.legacyKeychain.removeAll()
        }
        debugLog("[Keychain] All Keychain items and in-memory session/team cleared.")
    }
}
