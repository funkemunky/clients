import { mock } from "jest-mock-extended";
import { Subject } from "rxjs";

import { CollectionService } from "@bitwarden/admin-console/common";
import { ApiService } from "@bitwarden/common/abstractions/api.service";
import { AccountService } from "@bitwarden/common/auth/abstractions/account.service";
import { AuthService } from "@bitwarden/common/auth/abstractions/auth.service";
import { LogService } from "@bitwarden/common/platform/abstractions/log.service";
import { StateService } from "@bitwarden/common/platform/abstractions/state.service";
import { MessageListener, MessageSender } from "@bitwarden/common/platform/messaging";
import { Utils } from "@bitwarden/common/platform/misc/utils";
import { FakeStateProvider, mockAccountServiceWith } from "@bitwarden/common/spec";
import { SendApiService } from "@bitwarden/common/tools/send/services/send-api.service.abstraction";
import { InternalSendService } from "@bitwarden/common/tools/send/services/send.service.abstraction";
import { UserId } from "@bitwarden/common/types/guid";
import { CipherService } from "@bitwarden/common/vault/abstractions/cipher.service";
import { FolderApiServiceAbstraction } from "@bitwarden/common/vault/abstractions/folder/folder-api.service.abstraction";
import { InternalFolderService } from "@bitwarden/common/vault/abstractions/folder/folder.service.abstraction";

import { DO_FULL_SYNC, ForegroundSyncService, FullSyncMessage } from "./foreground-sync.service";
import { FullSyncFinishedMessage } from "./sync-service.listener";

describe("ForegroundSyncService", () => {
  const userId = Utils.newGuid() as UserId;
  const stateService = mock<StateService>();
  const folderService = mock<InternalFolderService>();
  const folderApiService = mock<FolderApiServiceAbstraction>();
  const messageSender = mock<MessageSender>();
  const logService = mock<LogService>();
  const cipherService = mock<CipherService>();
  const collectionService = mock<CollectionService>();
  const apiService = mock<ApiService>();
  const accountService = mock<AccountService>();
  const authService = mock<AuthService>();
  const sendService = mock<InternalSendService>();
  const sendApiService = mock<SendApiService>();
  const messageListener = mock<MessageListener>();
  const stateProvider = new FakeStateProvider(mockAccountServiceWith(userId));

  const sut = new ForegroundSyncService(
    stateService,
    folderService,
    folderApiService,
    messageSender,
    logService,
    cipherService,
    collectionService,
    apiService,
    accountService,
    authService,
    sendService,
    sendApiService,
    messageListener,
    stateProvider,
  );

  beforeEach(() => {
    jest.resetAllMocks();
  });

  describe("fullSync", () => {
    const getAndAssertRequestId = (doFullSyncMessage: Omit<FullSyncMessage, "requestId">) => {
      expect(messageSender.send).toHaveBeenCalledWith(
        DO_FULL_SYNC,
        // We don't know the request id since that is created internally
        expect.objectContaining(doFullSyncMessage),
      );

      const message = messageSender.send.mock.calls[0][1];

      if (!("requestId" in message) || typeof message.requestId !== "string") {
        throw new Error("requestId property of type string was expected on the sent message.");
      }

      return message.requestId;
    };

    it("correctly relays a successful fullSync", async () => {
      const messages = new Subject<FullSyncFinishedMessage>();
      messageListener.messages$.mockReturnValue(messages);
      const fullSyncPromise = sut.fullSync(true, false);
      expect(sut.syncInProgress).toBe(true);

      const requestId = getAndAssertRequestId({ forceSync: true, allowThrowOnError: false });

      // Pretend the sync has finished
      messages.next({ successfully: true, errorMessage: null, requestId: requestId });

      const result = await fullSyncPromise;

      expect(sut.syncInProgress).toBe(false);
      expect(result).toBe(true);
    });

    it("correctly relays an unsuccessful fullSync but does not throw if allowThrowOnError = false", async () => {
      const messages = new Subject<FullSyncFinishedMessage>();
      messageListener.messages$.mockReturnValue(messages);
      const fullSyncPromise = sut.fullSync(false, false);
      expect(sut.syncInProgress).toBe(true);

      const requestId = getAndAssertRequestId({ forceSync: false, allowThrowOnError: false });

      // Pretend the sync has finished
      messages.next({
        successfully: false,
        errorMessage: "Error while syncing",
        requestId: requestId,
      });

      const result = await fullSyncPromise;

      expect(sut.syncInProgress).toBe(false);
      expect(result).toBe(false);
    });

    it("correctly relays an unsuccessful fullSync but and will throw if allowThrowOnError = true", async () => {
      const messages = new Subject<FullSyncFinishedMessage>();
      messageListener.messages$.mockReturnValue(messages);
      const fullSyncPromise = sut.fullSync(true, true);
      expect(sut.syncInProgress).toBe(true);

      const requestId = getAndAssertRequestId({ forceSync: true, allowThrowOnError: true });

      // Pretend the sync has finished
      messages.next({
        successfully: false,
        errorMessage: "Error while syncing",
        requestId: requestId,
      });

      await expect(fullSyncPromise).rejects.toThrow("Error while syncing");

      expect(sut.syncInProgress).toBe(false);
    });
  });
});
