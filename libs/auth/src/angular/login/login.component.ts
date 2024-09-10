import { CommonModule } from "@angular/common";
import { Component, ElementRef, Input, NgZone, OnDestroy, OnInit, ViewChild } from "@angular/core";
import { FormBuilder, ReactiveFormsModule, Validators } from "@angular/forms";
import { ActivatedRoute, Router, RouterModule } from "@angular/router";
import { first, firstValueFrom, of, Subject, switchMap, take, takeUntil } from "rxjs";

import { JslibModule } from "@bitwarden/angular/jslib.module";
import {
  LoginEmailServiceAbstraction,
  LoginStrategyServiceAbstraction,
  PasswordLoginCredentials,
  RegisterRouteService,
} from "@bitwarden/auth/common";
import { InternalPolicyService } from "@bitwarden/common/admin-console/abstractions/policy/policy.service.abstraction";
import { PolicyData } from "@bitwarden/common/admin-console/models/data/policy.data";
import { MasterPasswordPolicyOptions } from "@bitwarden/common/admin-console/models/domain/master-password-policy-options";
import { Policy } from "@bitwarden/common/admin-console/models/domain/policy";
import { DevicesApiServiceAbstraction } from "@bitwarden/common/auth/abstractions/devices-api.service.abstraction";
import { CaptchaIFrame } from "@bitwarden/common/auth/captcha-iframe";
import { AuthResult } from "@bitwarden/common/auth/models/domain/auth-result";
import { ForceSetPasswordReason } from "@bitwarden/common/auth/models/domain/force-set-password-reason";
import { ClientType } from "@bitwarden/common/enums";
import { AppIdService } from "@bitwarden/common/platform/abstractions/app-id.service";
import { EnvironmentService } from "@bitwarden/common/platform/abstractions/environment.service";
import { I18nService } from "@bitwarden/common/platform/abstractions/i18n.service";
import { PlatformUtilsService } from "@bitwarden/common/platform/abstractions/platform-utils.service";
import { Utils } from "@bitwarden/common/platform/misc/utils";
import { SyncService } from "@bitwarden/common/platform/sync";
import { PasswordStrengthServiceAbstraction } from "@bitwarden/common/tools/password-strength";
import { UserId } from "@bitwarden/common/types/guid";
import {
  AsyncActionsModule,
  ButtonModule,
  CheckboxModule,
  FormFieldModule,
  IconButtonModule,
  ToastService,
} from "@bitwarden/components";

import { LoginService } from "./login.service";

@Component({
  standalone: true,
  templateUrl: "./login.component.html",
  imports: [
    AsyncActionsModule,
    ButtonModule,
    CheckboxModule,
    CommonModule,
    FormFieldModule,
    IconButtonModule,
    JslibModule,
    ReactiveFormsModule,
    RouterModule,
  ],
})
export class LoginComponentV2 implements OnInit, OnDestroy {
  @ViewChild("masterPasswordInput", { static: true }) masterPasswordInput: ElementRef;
  @Input() captchaSiteKey: string = null;

  private destroy$ = new Subject<void>();

  captcha: CaptchaIFrame;
  captchaToken: string = null;
  clientType: ClientType;
  ClientType = ClientType;
  registerRoute$ = this.registerRouteService.registerRoute$(); // TODO: remove when email verification flag is removed
  showLoginWithDevice = false;
  validatedEmail = false;

  formGroup = this.formBuilder.group({
    email: ["", [Validators.required, Validators.email]],
    masterPassword: [
      "",
      [Validators.required, Validators.minLength(Utils.originalMinimumPasswordLength)],
    ],
    rememberEmail: [false],
  });

  get emailFormControl() {
    return this.formGroup.controls.email;
  }

  get loggedEmail() {
    return this.formGroup.value.email;
  }

  // Web specific properties
  enforcedPasswordPolicyOptions: MasterPasswordPolicyOptions;
  policies: Policy[];
  showPasswordless = false;
  showResetPasswordAutoEnrollWarning = false;

  constructor(
    private activatedRoute: ActivatedRoute,
    private appIdService: AppIdService,
    private devicesApiService: DevicesApiServiceAbstraction,
    private environmentService: EnvironmentService,
    private formBuilder: FormBuilder,
    private i18nService: I18nService,
    private loginEmailService: LoginEmailServiceAbstraction,
    private loginService: LoginService,
    private loginStrategyService: LoginStrategyServiceAbstraction,
    private ngZone: NgZone,
    private passwordStrengthService: PasswordStrengthServiceAbstraction,
    private platformUtilsService: PlatformUtilsService,
    private policyService: InternalPolicyService,
    private registerRouteService: RegisterRouteService,
    private router: Router,
    private syncService: SyncService,
    private toastService: ToastService,
  ) {
    this.clientType = this.platformUtilsService.getClientType();
    this.showPasswordless = this.loginService.getShowPasswordlessFlag();
  }

  async ngOnInit(): Promise<void> {
    if (this.clientType === ClientType.Web) {
      await this.webOnInit();
    }

    await this.defaultOnInit();

    if (this.clientType === ClientType.Web) {
      // If there's an existing org invite, use it to get the password policies
      const orgPolicies = await this.loginService.getOrgPolicies();

      this.policies = orgPolicies?.policies;
      this.showResetPasswordAutoEnrollWarning = orgPolicies?.isPolicyAndAutoEnrollEnabled;
      this.enforcedPasswordPolicyOptions = orgPolicies?.enforcedPasswordPolicyOptions;
    }

    if (this.clientType === ClientType.Browser) {
      if (this.showPasswordless) {
        await this.validateEmail();
      }
    }
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  submit = async (showToast = true): Promise<void> => {
    const data = this.formGroup.value;

    await this.setupCaptcha();

    this.formGroup.markAllAsTouched();

    // Web specific (start)
    if (this.formGroup.invalid && !showToast) {
      return;
    }
    // Web specific (end)

    // TODO-rr-bw: handle toast here for Browser/Desktop? See base LoginComponent -> submit()

    const credentials = new PasswordLoginCredentials(
      data.email,
      data.masterPassword,
      this.captchaToken,
      null,
    );

    const authResult = await this.loginStrategyService.logIn(credentials);

    await this.saveEmailSettings();

    if (this.handleCaptchaRequired(authResult)) {
      return;
    }

    if (authResult.requiresEncryptionKeyMigration) {
      /* Legacy accounts used the master key to encrypt data.
         Migration is required but only performed on Web. */
      if (this.clientType === ClientType.Web) {
        await this.router.navigate(["migrate-legacy-encryption"]);
      } else {
        this.toastService.showToast({
          variant: "error",
          title: this.i18nService.t("errorOccured"),
          message: this.i18nService.t("encryptionKeyMigrationRequired"),
        });
      }
    } else if (authResult.requiresTwoFactor) {
      await this.router.navigate(["2fa"]);
    } else if (authResult.forcePasswordReset != ForceSetPasswordReason.None) {
      this.loginEmailService.clearValues();
      await this.router.navigate(["update-temp-password"]);
    } else {
      if (this.clientType === ClientType.Web) {
        await this.goAfterLogIn(authResult.userId);
      } else {
        await this.syncService.fullSync(true); // TODO-rr-bw: browser used `await`, desktop used `return`. Why?

        this.loginEmailService.clearValues();

        if (this.clientType === ClientType.Browser) {
          await this.router.navigate(["/tabs/vault"]);
        } else {
          await this.router.navigate(["vault"]); // Desktop
        }
      }
    }
  };

  protected async goAfterLogIn(userId: UserId): Promise<void> {
    const masterPassword = this.formGroup.value.masterPassword;

    // Check master password against policy
    if (this.enforcedPasswordPolicyOptions != null) {
      const strengthResult = this.passwordStrengthService.getPasswordStrength(
        masterPassword,
        this.formGroup.value.email,
      );
      const masterPasswordScore = strengthResult == null ? null : strengthResult.score;

      // If invalid, save policies and require update
      if (
        !this.policyService.evaluateMasterPassword(
          masterPasswordScore,
          masterPassword,
          this.enforcedPasswordPolicyOptions,
        )
      ) {
        const policiesData: { [id: string]: PolicyData } = {};
        this.policies.map((p) => (policiesData[p.id] = PolicyData.fromPolicy(p)));
        await this.policyService.replace(policiesData, userId);
        await this.router.navigate(["update-password"]);
        return;
      }
    }

    this.loginEmailService.clearValues();
    await this.router.navigate(["vault"]);
  }

  protected showCaptcha(): boolean {
    return !Utils.isNullOrWhitespace(this.captchaSiteKey);
  }

  protected async startAuthRequestLogin(): Promise<void> {
    this.formGroup.get("masterPassword")?.clearValidators();
    this.formGroup.get("masterPassword")?.updateValueAndValidity();

    if (!this.formGroup.valid) {
      return;
    }

    await this.saveEmailSettings();
    await this.router.navigate(["/login-with-device"]);
  }

  protected async validateEmail(): Promise<void> {
    this.formGroup.controls.email.markAsTouched();
    const emailValid = this.formGroup.controls.email.valid;

    if (emailValid) {
      this.toggleValidateEmail(true);
      await this.getLoginWithDevice(this.loggedEmail);
    }
  }

  protected toggleValidateEmail(value: boolean): void {
    this.validatedEmail = value;

    if (!this.validatedEmail) {
      // Reset master password only when going from validated to not validated so that autofill can work properly
      this.formGroup.controls.masterPassword.reset();
    } else {
      // Mark MP as untouched so that, when users enter email and hit enter, the MP field doesn't load with validation errors
      this.formGroup.controls.masterPassword.markAsUntouched();

      // When email is validated, focus on master password after waiting for input to be rendered
      if (this.ngZone.isStable) {
        this.masterPasswordInput?.nativeElement?.focus();
      } else {
        this.ngZone.onStable.pipe(take(1), takeUntil(this.destroy$)).subscribe(() => {
          this.masterPasswordInput?.nativeElement?.focus();
        });
      }
    }
  }

  protected async goToHint(): Promise<void> {
    await this.saveEmailSettings();
    await this.router.navigateByUrl("/hint");
  }

  protected async goToRegister(): Promise<void> {
    // TODO: remove when email verification flag is removed
    const registerRoute = await firstValueFrom(this.registerRoute$);

    if (this.emailFormControl.valid) {
      await this.router.navigate([registerRoute], {
        queryParams: { email: this.emailFormControl.value },
      });
      return;
    }

    await this.router.navigate([registerRoute]);
  }

  protected async saveEmailSettings(): Promise<void> {
    this.loginEmailService.setLoginEmail(this.formGroup.value.email);
    this.loginEmailService.setRememberEmail(this.formGroup.value.rememberEmail);
    await this.loginEmailService.saveEmailSettings();
  }

  private async getLoginWithDevice(email: string): Promise<void> {
    try {
      const deviceIdentifier = await this.appIdService.getAppId();
      this.showLoginWithDevice = await this.devicesApiService.getKnownDevice(
        email,
        deviceIdentifier,
      );
    } catch (e) {
      this.showLoginWithDevice = false;
    }
  }

  private async setupCaptcha(): Promise<void> {
    const env = await firstValueFrom(this.environmentService.environment$);
    const webVaultUrl = env.getWebVaultUrl();

    this.captcha = new CaptchaIFrame(
      window,
      webVaultUrl,
      this.i18nService,
      (token: string) => {
        this.captchaToken = token;
      },
      (error: string) => {
        this.toastService.showToast({
          variant: "error",
          title: this.i18nService.t("errorOccurred"),
          message: error,
        });
      },
      (info: string) => {
        this.toastService.showToast({
          variant: "info",
          title: this.i18nService.t("info"),
          message: info,
        });
      },
    );
  }

  private handleCaptchaRequired(authResult: AuthResult): boolean {
    if (Utils.isNullOrWhitespace(authResult.captchaSiteKey)) {
      return false;
    }

    this.captchaSiteKey = authResult.captchaSiteKey;
    this.captcha.init(authResult.captchaSiteKey);
    return true;
  }

  private async loadEmailSettings(): Promise<void> {
    // Try to load the email from memory first
    const email = await firstValueFrom(this.loginEmailService.loginEmail$);
    const rememberEmail = this.loginEmailService.getRememberEmail();

    if (email) {
      this.formGroup.controls.email.setValue(email);
      this.formGroup.controls.rememberEmail.setValue(rememberEmail);
    } else {
      // If there is no email in memory, check for a storedEmail on disk
      const storedEmail = await firstValueFrom(this.loginEmailService.storedEmail$);

      if (storedEmail) {
        this.formGroup.controls.email.setValue(storedEmail);
        this.formGroup.controls.rememberEmail.setValue(true); // If there is a storedEmail, rememberEmail defaults to true
      }
    }
  }

  private async defaultOnInit(): Promise<void> {
    let paramEmailIsSet = false;

    this.activatedRoute?.queryParams
      .pipe(
        switchMap((params) => {
          if (!params) {
            // If no params,loadEmailSettings from state
            return this.loadEmailSettings();
          }

          const qParamsEmail = params.email;

          // If there is an email in the query params, set that email as the form field value
          if (qParamsEmail != null && qParamsEmail.indexOf("@") > -1) {
            this.formGroup.controls.email.setValue(qParamsEmail);
            paramEmailIsSet = true;
          }

          // If there is no email in the query params, loadEmailSettings from state
          return paramEmailIsSet ? of(null) : this.loadEmailSettings();
        }),
        takeUntil(this.destroy$),
      )
      .subscribe();

    // Backup check to handle unknown case where activatedRoute is not available
    // This shouldn't happen under normal circumstances
    if (!this.activatedRoute) {
      await this.loadEmailSettings();
    }
  }

  private async webOnInit(): Promise<void> {
    this.activatedRoute.queryParams.pipe(first(), takeUntil(this.destroy$)).subscribe((qParams) => {
      // If there is a parameter called 'org', set previousUrl to `/create-organization?org=<paramValue>`
      if (qParams.org != null) {
        const route = this.router.createUrlTree(["create-organization"], {
          queryParams: { plan: qParams.org },
        });
        this.loginService.setPreviousUrl(route);
      }

      /**
       * If there is a parameter called 'sponsorshipToken', they are coming from an email for sponsoring a families organization.
       * Therefore set the prevousUrl to `/setup/families-for-enterprise?token=<paramValue>`
       */
      if (qParams.sponsorshipToken != null) {
        const route = this.router.createUrlTree(["setup/families-for-enterprise"], {
          queryParams: { token: qParams.sponsorshipToken },
        });
        this.loginService.setPreviousUrl(route);
      }
    });
  }
}