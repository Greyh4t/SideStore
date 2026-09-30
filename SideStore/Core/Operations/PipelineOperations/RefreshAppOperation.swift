//
//  RefreshAppOperation.swift
//  AltStore
//
//  Created by Riley Testut on 2/27/20.
//  Copyright © 2020 Riley Testut. All rights reserved.
//

import Foundation
import CoreData
@preconcurrency import AltSign

final class RefreshAppOperation: BasePipelineOperation<InstallAppOperationContext, InstalledApp>, @unchecked Sendable {
    
    override func execute(parentProgress: Progress?) async throws -> InstalledApp {
        debugLog("[RefreshAppOperation] execute() started")
        defer { debugLog("[RefreshAppOperation] execute() completed") }
        try await super.executePreconditionCheck(parentProgress: parentProgress)
        
        guard let profiles = self.context.provisioningProfiles else {
            throw OperationError.invalidParameters("RefreshAppOperation.execute: self.context.provisioningProfiles is nil")
        }
        
        guard let appBundle = self.context.targetAppBundle else { throw OperationError(.appNotFound(name: nil)) }
        // A successful misagent install only confirms that iOS accepted the profile.
        // It does not verify that PlugInKit can launch an installed app extension.
        debugLog("[RefreshAppOperation] Profile-only refresh: useMainProfile=\(self.context.useMainProfile), profiles=\(profiles.count), extensions=\(appBundle.appExtensions.count)")
        for appExtension in appBundle.appExtensions {
            let identifier = appExtension.entitlements[.applicationIdentifier] as? String ?? "missing"
            let embeddedExpiry = appExtension.provisioningProfile?.expirationDate.description ?? "missing"
            debugLog("[RefreshAppOperation] Extension \(appExtension.bundleIdentifier): signedApplicationIdentifier=\(identifier), cachedEmbeddedExpiry=\(embeddedExpiry)")
        }
        self.setProgress(10)
        for p in profiles {
            let identifier = p.value.entitlements[.applicationIdentifier] as? String ?? "missing"
            debugLog("[RefreshAppOperation] Installing profile for \(p.key): applicationIdentifier=\(identifier), expires=\(p.value.expirationDate)")
            do {
                try await installProvisioningProfiles(p.value.data)
            } catch {
                // Preserve the device/pairing/misagent failure returned by minimuxer.
                // Replacing every failure with .profileInstall hides whether the
                // request ever reached misagent and makes connection failures look
                // like provisioning-profile signing errors.
                debugLog("[RefreshAppOperation] profile installation failed: \(error.localizedDescription)")
                throw error
            }
        }
        
        self.setProgress(80)
        guard let dbContext = self.context.dbBackgroundContext else {
            throw OperationError.invalidParameters("RefreshAppOperation: context.dbBackgroundContext is nil")
        }
        
        let installedApp = try await dbContext.perform {
            try self.updateInstalledApp(for: appBundle, profiles: profiles, in: dbContext)
        }
        
        self.setProgress(100)
        return installedApp
    }
    
    private func updateInstalledApp(for appBundle: ALTApplication, profiles: [String: ALTProvisioningProfile], in dbContext: NSManagedObjectContext) throws -> InstalledApp {
        self.setProgress(self.progress.completedUnitCount + 1)
        
        guard let mainApp = self.context.installedApp,
              let installedApp = dbContext.object(with: mainApp.objectID) as? InstalledApp else {
            throw OperationError(.appNotFound(name: appBundle.name))
        }
        guard let mainProfile = profiles[self.context.targetBundleIdentifier] else {
            throw OperationError.invalidParameters("RefreshAppOperation: main provisioning profile is missing")
        }
        installedApp.update(provisioningProfile: mainProfile)
        
        if let certStatus = self.context.targetCertStatus {
            installedApp.certificateStatus = certStatus
        }

        for installedExtension in installedApp.appExtensions {
            let profileIdentifier = installedExtension.bundleIdentifier.replacingOccurrences(
                of: self.context.bundleIdentifier,
                with: self.context.targetBundleIdentifier
            )
            guard let provisioningProfile = self.context.useMainProfile ? mainProfile : profiles[profileIdentifier] else { continue }
            installedExtension.update(provisioningProfile: provisioningProfile)
        }
        return installedApp
    }
}
