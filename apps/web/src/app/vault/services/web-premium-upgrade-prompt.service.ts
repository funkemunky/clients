import { DialogRef } from "@angular/cdk/dialog";
import { Injectable } from "@angular/core";
import { Router } from "@angular/router";

import { OrganizationId } from "@bitwarden/common/types/guid";
import { PremiumUpgradePromptService } from "@bitwarden/common/vault/abstractions/premium-upgrade-prompt.service";
import { DialogService } from "@bitwarden/components";

import {
  ViewCipherDialogCloseResult,
  ViewCipherDialogResult,
} from "../individual-vault/view.component";

/**
 * This service is used to prompt the user to upgrade to premium.
 */
@Injectable()
export class WebVaultPremiumUpgradePromptService implements PremiumUpgradePromptService {
  constructor(
    private dialogService: DialogService,
    private router: Router,
    private dialog: DialogRef<ViewCipherDialogCloseResult>,
  ) {}

  /**
   * Prompts the user to upgrade to premium.
   * @param organizationId The ID of the organization to upgrade.
   */
  async promptForPremium(organizationId?: OrganizationId) {
    let upgradeConfirmed;
    if (organizationId) {
      upgradeConfirmed = await this.dialogService.openSimpleDialog({
        title: { key: "upgradeOrganization" },
        content: { key: "upgradeOrganizationDesc" },
        acceptButtonText: { key: "upgradeOrganization" },
        type: "info",
      });
      if (upgradeConfirmed) {
        await this.router.navigate(["organizations", organizationId, "billing", "subscription"]);
      }
    } else {
      upgradeConfirmed = await this.dialogService.openSimpleDialog({
        title: { key: "premiumRequired" },
        content: { key: "premiumRequiredDesc" },
        acceptButtonText: { key: "upgrade" },
        type: "success",
      });
      if (upgradeConfirmed) {
        await this.router.navigate(["settings/subscription/premium"]);
      }
    }

    if (upgradeConfirmed) {
      this.dialog.close({ action: ViewCipherDialogResult.PremiumUpgrade });
    }
  }
}