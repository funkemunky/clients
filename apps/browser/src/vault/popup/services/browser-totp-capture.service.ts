import { Injectable } from "@angular/core";
import qrcodeParser from "qrcode-parser";

import { TotpCaptureService } from "@bitwarden/vault";

import { BrowserApi } from "../../../platform/browser/browser-api";

/**
 * Implementation of TotpCaptureService for the browser which captures the
 * TOTP secret from the currently visible tab.
 */
@Injectable()
export class BrowserTotpCaptureService implements TotpCaptureService {
  async captureTotpSecret() {
    const screenshot = await BrowserApi.captureVisibleTab();
    const data = await qrcodeParser(screenshot);
    const url = new URL(data.toString());
    if (url.protocol === "otpauth:" && url.searchParams.has("secret")) {
      return data.toString();
    }
    return null;
  }

  async openAutofillNewTab(loginUri: string) {
    await BrowserApi.createNewTab(loginUri);
  }
}
