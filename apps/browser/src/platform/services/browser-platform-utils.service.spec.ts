import { DeviceType } from "@bitwarden/common/enums";

import { flushPromises } from "../../autofill/jest/testing-utils";
import { SafariApp } from "../../browser/safariApp";
import { BrowserApi } from "../browser/browser-api";

import BrowserClipboardService from "./browser-clipboard.service";
import BrowserPlatformUtilsService from "./browser-platform-utils.service";

describe("Browser Utils Service", () => {
  let browserPlatformUtilsService: BrowserPlatformUtilsService;
  const clipboardWriteCallbackSpy = jest.fn();

  beforeEach(() => {
    (window as any).matchMedia = jest.fn().mockReturnValueOnce({});
    browserPlatformUtilsService = new BrowserPlatformUtilsService(
      null,
      clipboardWriteCallbackSpy,
      null,
      window,
    );
  });

  describe("getBrowser", () => {
    const originalUserAgent = navigator.userAgent;
    // Reset the userAgent.
    afterAll(() => {
      Object.defineProperty(navigator, "userAgent", {
        value: originalUserAgent,
      });
    });

    beforeEach(() => {
      (window as any).matchMedia = jest.fn().mockReturnValueOnce({});
    });

    afterEach(() => {
      window.matchMedia = undefined;
      (BrowserPlatformUtilsService as any).deviceCache = null;
    });

    it("should detect chrome", () => {
      Object.defineProperty(navigator, "userAgent", {
        configurable: true,
        value:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
      });

      expect(browserPlatformUtilsService.getDevice()).toBe(DeviceType.ChromeExtension);
    });

    it("should detect firefox", () => {
      Object.defineProperty(navigator, "userAgent", {
        configurable: true,
        value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0",
      });

      expect(browserPlatformUtilsService.getDevice()).toBe(DeviceType.FirefoxExtension);
    });

    it("should detect opera", () => {
      Object.defineProperty(navigator, "userAgent", {
        configurable: true,
        value:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3175.3 Safari/537.36 OPR/49.0.2695.0 (Edition developer)",
      });

      expect(browserPlatformUtilsService.getDevice()).toBe(DeviceType.OperaExtension);
    });

    it("should detect edge", () => {
      Object.defineProperty(navigator, "userAgent", {
        configurable: true,
        value:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.74 Safari/537.36 Edg/79.0.309.43",
      });

      expect(browserPlatformUtilsService.getDevice()).toBe(DeviceType.EdgeExtension);
    });

    it("should detect safari", () => {
      Object.defineProperty(navigator, "userAgent", {
        configurable: true,
        value:
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/602.4.8 (KHTML, like Gecko) Version/10.0.3 Safari/602.4.8",
      });

      expect(browserPlatformUtilsService.getDevice()).toBe(DeviceType.SafariExtension);
    });

    it("should detect vivaldi", () => {
      Object.defineProperty(navigator, "userAgent", {
        configurable: true,
        value:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.97 Safari/537.36 Vivaldi/1.94.1008.40",
      });

      expect(browserPlatformUtilsService.getDevice()).toBe(DeviceType.VivaldiExtension);
    });

    it("returns a previously determined device using a cached value", () => {
      Object.defineProperty(navigator, "userAgent", {
        configurable: true,
        value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0",
      });
      jest.spyOn(BrowserPlatformUtilsService, "isFirefox");

      browserPlatformUtilsService.getDevice();

      expect(browserPlatformUtilsService.getDevice()).toBe(DeviceType.FirefoxExtension);
      expect(BrowserPlatformUtilsService.isFirefox).toHaveBeenCalledTimes(1);
    });
  });

  describe("getDeviceString", () => {
    it("returns a string value indicating the device type", () => {
      jest
        .spyOn(browserPlatformUtilsService, "getDevice")
        .mockReturnValue(DeviceType.ChromeExtension);

      expect(browserPlatformUtilsService.getDeviceString()).toBe("chrome");
    });
  });

  describe("isViewOpen", () => {
    it("returns true if the user is on Firefox and the sidebar is open", async () => {
      chrome.extension.getViews = jest.fn().mockReturnValueOnce([window]);
      jest
        .spyOn(browserPlatformUtilsService, "getDevice")
        .mockReturnValueOnce(DeviceType.FirefoxExtension);

      const result = await browserPlatformUtilsService.isViewOpen();

      expect(result).toBe(true);
    });

    it("returns true if a extension view is open as a tab", async () => {
      chrome.extension.getViews = jest.fn().mockReturnValueOnce([window]);

      const result = await browserPlatformUtilsService.isViewOpen();

      expect(result).toBe(true);
    });

    it("returns false if no extension view is open", async () => {
      chrome.extension.getViews = jest.fn().mockReturnValue([]);

      const result = await browserPlatformUtilsService.isViewOpen();

      expect(result).toBe(false);
    });
  });

  describe("copyToClipboard", () => {
    const getManifestVersionSpy = jest.spyOn(BrowserApi, "manifestVersion", "get");
    const sendMessageToAppSpy = jest.spyOn(SafariApp, "sendMessageToApp");
    const clipboardServiceCopySpy = jest.spyOn(BrowserClipboardService, "copy");
    let triggerOffscreenCopyToClipboardSpy: jest.SpyInstance;

    beforeEach(() => {
      triggerOffscreenCopyToClipboardSpy = jest.spyOn(
        browserPlatformUtilsService as any,
        "triggerOffscreenCopyToClipboard",
      );
    });

    afterEach(() => {
      jest.resetAllMocks();
    });

    it("sends a message to the desktop application if a user is using the safari browser", async () => {
      const text = "test";
      const clearMs = 1000;
      getManifestVersionSpy.mockReturnValue(2);
      sendMessageToAppSpy.mockResolvedValueOnce("success");
      jest
        .spyOn(browserPlatformUtilsService, "getDevice")
        .mockReturnValue(DeviceType.SafariExtension);

      browserPlatformUtilsService.copyToClipboard(text, { clearMs });
      await flushPromises();

      expect(sendMessageToAppSpy).toHaveBeenCalledWith("copyToClipboard", text);
      expect(clipboardWriteCallbackSpy).toHaveBeenCalledWith(text, clearMs);
      expect(clipboardServiceCopySpy).not.toHaveBeenCalled();
      expect(triggerOffscreenCopyToClipboardSpy).not.toHaveBeenCalled();
    });

    it("sets the copied text to a unicode placeholder when the user is using Chrome if the passed text is an empty string", async () => {
      const text = "";
      getManifestVersionSpy.mockReturnValue(2);
      jest
        .spyOn(browserPlatformUtilsService, "getDevice")
        .mockReturnValue(DeviceType.ChromeExtension);

      browserPlatformUtilsService.copyToClipboard(text);
      await flushPromises();

      expect(clipboardServiceCopySpy).toHaveBeenCalledWith(window, "\u0000");
    });

    it("copies the passed text using the BrowserClipboardService", async () => {
      const text = "test";
      getManifestVersionSpy.mockReturnValue(2);
      jest
        .spyOn(browserPlatformUtilsService, "getDevice")
        .mockReturnValue(DeviceType.ChromeExtension);

      browserPlatformUtilsService.copyToClipboard(text, { window: self });
      await flushPromises();

      expect(clipboardServiceCopySpy).toHaveBeenCalledWith(self, text);
      expect(triggerOffscreenCopyToClipboardSpy).not.toHaveBeenCalled();
    });

    it("copies the passed text using the offscreen document if the extension is using manifest v3", async () => {
      const text = "test";
      jest
        .spyOn(browserPlatformUtilsService, "getDevice")
        .mockReturnValue(DeviceType.ChromeExtension);
      getManifestVersionSpy.mockReturnValue(3);
      jest.spyOn(BrowserApi, "createOffscreenDocument");
      jest.spyOn(BrowserApi, "sendMessageWithResponse").mockResolvedValue(undefined);
      jest.spyOn(BrowserApi, "closeOffscreenDocument");

      browserPlatformUtilsService.copyToClipboard(text);
      await flushPromises();

      expect(triggerOffscreenCopyToClipboardSpy).toHaveBeenCalledWith(text);
      expect(clipboardServiceCopySpy).not.toHaveBeenCalled();
      expect(BrowserApi.createOffscreenDocument).toHaveBeenCalledWith(
        ["clipboard"],
        "Write text to the clipboard.",
      );
      expect(BrowserApi.sendMessageWithResponse).toHaveBeenCalledWith("offscreenCopyToClipboard", {
        text,
      });
      expect(BrowserApi.closeOffscreenDocument).toHaveBeenCalled();
    });

    it("skips the clipboardWriteCallback if the clipboard is clearing", async () => {
      getManifestVersionSpy.mockReturnValue(2);
      jest
        .spyOn(browserPlatformUtilsService, "getDevice")
        .mockReturnValue(DeviceType.ChromeExtension);

      browserPlatformUtilsService.copyToClipboard("test", { window: self, clearing: true });
      await flushPromises();

      expect(clipboardWriteCallbackSpy).not.toHaveBeenCalled();
    });
  });
});

describe("Safari Height Fix", () => {
  const originalUserAgent = navigator.userAgent;

  // Reset the userAgent.
  afterAll(() => {
    Object.defineProperty(navigator, "userAgent", {
      value: originalUserAgent,
    });
  });

  afterEach(() => {
    (BrowserPlatformUtilsService as any).deviceCache = null;
  });

  test.each([
    [
      "safari 15.6.1",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.1 Safari/605.1.15",
      true,
    ],
    [
      "safari 16.0",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
      true,
    ],

    [
      "safari 16.1",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
      false,
    ],
    [
      "safari 16.4",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
      false,
    ],
    [
      "safari 17.0 (future release)",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
      false,
    ],
    [
      "chrome",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36",
      false,
    ],
    [
      "firefox",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0",
      false,
    ],
    [
      "opera",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3175.3 Safari/537.36 OPR/49.0.2695.0 (Edition developer)",
      false,
    ],
    [
      "edge",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.74 Safari/537.36 Edg/79.0.309.43",
      false,
    ],
  ])("Apply fix for %s", (name, userAgent, expected) => {
    Object.defineProperty(navigator, "userAgent", {
      configurable: true,
      value: userAgent,
    });
    expect(BrowserPlatformUtilsService.shouldApplySafariHeightFix(window)).toBe(expected);
  });
});
