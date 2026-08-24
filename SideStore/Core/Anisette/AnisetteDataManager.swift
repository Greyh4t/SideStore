//
//  AnisetteDataManager.swift
//  SideStore
//
//  Created by Magesh K on 8/3/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation

public final class AnisetteDataManager: @unchecked Sendable {
    public static let shared = AnisetteDataManager()
    
    private init() {}
    
    public var anisetteIdentifier: String? {
        get { LiveProcessEphemeralAuthentication.current()?.anisetteIdentifier ?? Keychain.shared.identifier }
        set { Keychain.shared.identifier = newValue }
    }
    
    public var anisetteAdiBlob: String? {
        get { LiveProcessEphemeralAuthentication.current()?.anisetteAdiPb ?? Keychain.shared.adiPb }
        set { Keychain.shared.adiPb = newValue }
    }
}
