import { TestBed } from "@angular/core/testing";

import { AuditService } from "@bitwarden/common/abstractions/audit.service";
import { PasswordStrengthServiceAbstraction } from "@bitwarden/common/tools/password-strength";
import { CipherService } from "@bitwarden/common/vault/abstractions/cipher.service";
import { CipherType } from "@bitwarden/common/vault/enums";
import { CipherView } from "@bitwarden/common/vault/models/view/cipher.view";
import { LoginView } from "@bitwarden/common/vault/models/view/login.view";

import { mockCiphers } from "./ciphers.mock";
import { MemberCipherDetailsApiService } from "./member-cipher-details-api.service";
import { mockMemberCipherDetails } from "./member-cipher-details-api.service.spec";
import { PasswordHealthService } from "./password-health.service";

describe("PasswordHealthService", () => {
  let service: PasswordHealthService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        PasswordHealthService,
        {
          provide: PasswordStrengthServiceAbstraction,
          useValue: {
            getPasswordStrength: (password: string) => {
              const score = password.length < 4 ? 1 : 4;
              return { score };
            },
          },
        },
        {
          provide: AuditService,
          useValue: {
            passwordLeaked: (password: string) => Promise.resolve(password === "123" ? 100 : 0),
          },
        },
        {
          provide: CipherService,
          useValue: {
            getAllFromApiForOrganization: jest.fn().mockResolvedValue(mockCiphers),
          },
        },
        {
          provide: MemberCipherDetailsApiService,
          useValue: {
            getMemberCipherDetails: jest.fn().mockResolvedValue(mockMemberCipherDetails),
          },
        },
      ],
    });

    service = TestBed.inject(PasswordHealthService);
  });

  it("should build the application health report correctly", async () => {
    // Execute the method
    const result = await service.generateReportDetails("orgId");

    const expected = [
      {
        application: "101domain.com",
        atRiskPasswords: 1,
        totalPasswords: 2,
        atRiskMembers: 2,
        totalMembers: 4,
      },
      {
        application: "123formbuilder.com",
        atRiskPasswords: 0,
        totalPasswords: 1,
        atRiskMembers: 0,
        totalMembers: 5,
      },
      {
        application: "example.com",
        atRiskPasswords: 1,
        totalPasswords: 2,
        atRiskMembers: 5,
        totalMembers: 5,
      },
      {
        application: "google.com",
        atRiskPasswords: 1,
        totalPasswords: 1,
        atRiskMembers: 2,
        totalMembers: 2,
      },
    ];

    // Sort for comparison
    const sortFn = (a: any, b: any) => a.application.localeCompare(b.application);

    expect(result.details.sort(sortFn)).toEqual(expected.sort(sortFn));
    expect(result.totalAtRiskMembers).toBe(5);
    expect(result.totalMembers).toBe(6);
    expect(result.totalAtRiskApps).toBe(3);
    expect(result.totalApps).toBe(4);
  });

  describe("isWeakPassword", () => {
    it("should return true for a weak password", () => {
      const cipher = new CipherView();
      cipher.type = CipherType.Login;
      cipher.login = { password: "123", username: "user" } as LoginView;
      cipher.viewPassword = true;

      expect(service.isWeakPassword(cipher)).toBe(true);
    });

    it("should return false for a strong password", () => {
      const cipher = new CipherView();
      cipher.type = CipherType.Login;
      cipher.login = { password: "StrongPass!123", username: "user" } as LoginView;
      cipher.viewPassword = true;

      expect(service.isWeakPassword(cipher)).toBe(false);
    });
  });

  describe("isReusedPassword", () => {
    it("should return false for a new password", () => {
      const cipher = new CipherView();
      cipher.type = CipherType.Login;
      cipher.login = { password: "uniquePassword", username: "user" } as LoginView;
      cipher.viewPassword = true;

      expect(service.isReusedPassword(cipher)).toBe(false);
    });

    it("should return true for a reused password", () => {
      const cipher1 = new CipherView();
      cipher1.type = CipherType.Login;
      cipher1.login = { password: "reusedPassword", username: "user" } as LoginView;
      cipher1.viewPassword = true;

      const cipher2 = new CipherView();
      cipher2.type = CipherType.Login;
      cipher2.login = { password: "reusedPassword", username: "user" } as LoginView;
      cipher2.viewPassword = true;

      service.isReusedPassword(cipher1); // Adds 'reusedPassword' to usedPasswords

      expect(service.isReusedPassword(cipher2)).toBe(true);
    });
  });
});
