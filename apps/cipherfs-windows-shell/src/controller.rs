//! Pure application state transitions used by the Slint adapter and deterministic tests.

use std::path::PathBuf;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Route {
    Help,
    Container(PathBuf),
    Pack { source: PathBuf, output: PathBuf },
    Form(FormKind),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FormKind {
    Mount(PathBuf),
    Extract { container: PathBuf, output: PathBuf },
    Verify(PathBuf),
    ChangePassword(PathBuf),
    Pack { source: PathBuf, output: PathBuf },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DialogOutcome<T> {
    Selected(T),
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AppErrorKind {
    NativeDialog,
    Operation,
    Mount,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Recovery {
    Close,
    Back,
    OpenUrl(&'static str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AppError {
    pub kind: AppErrorKind,
    pub message: String,
    pub recovery: Recovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AppPage {
    Help,
    Actions,
    Form,
    Progress,
    Mounted,
    Result,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AppAction {
    ShowRoute(Route),
    DialogCancelled,
    DialogFailed(String),
    OperationStarted,
    OperationProtected,
    OperationFinished(Result<(), String>),
    CancelPressed,
    Mounted,
    MountFailed(String),
    Unmounted(Result<(), String>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AppEffect {
    Render,
    RequestCooperativeCancel,
    ShowForceClose,
}

#[derive(Clone, Debug)]
pub(crate) struct AppState {
    pub page: AppPage,
    pub error: Option<AppError>,
    pub force_close_overlay: bool,
    cancel_requested: bool,
    protected: bool,
}

impl AppState {
    pub fn new(route: Route) -> Self {
        let page = match route {
            Route::Help => AppPage::Help,
            Route::Container(_) => AppPage::Actions,
            Route::Pack { .. } | Route::Form(_) => AppPage::Form,
        };
        Self {
            page,
            error: None,
            force_close_overlay: false,
            cancel_requested: false,
            protected: false,
        }
    }

    pub fn transition(&mut self, action: AppAction) -> Vec<AppEffect> {
        match action {
            AppAction::ShowRoute(route) => {
                *self = Self::new(route);
            }
            AppAction::DialogCancelled => {}
            AppAction::DialogFailed(message) => {
                self.page = AppPage::Error;
                self.error = Some(AppError {
                    kind: AppErrorKind::NativeDialog,
                    message,
                    recovery: Recovery::Back,
                });
            }
            AppAction::OperationStarted => {
                self.page = AppPage::Progress;
                self.cancel_requested = false;
                self.protected = false;
            }
            AppAction::OperationProtected => self.protected = true,
            AppAction::OperationFinished(result) => match result {
                Ok(()) => self.page = AppPage::Result,
                Err(message) if message == "Operation cancelled" => self.page = AppPage::Result,
                Err(message) => {
                    self.page = AppPage::Error;
                    self.error = Some(AppError {
                        kind: AppErrorKind::Operation,
                        message,
                        recovery: Recovery::Close,
                    });
                }
            },
            AppAction::CancelPressed if self.protected => {}
            AppAction::CancelPressed if self.cancel_requested => {
                self.force_close_overlay = true;
                return vec![AppEffect::ShowForceClose];
            }
            AppAction::CancelPressed => {
                self.cancel_requested = true;
                return vec![AppEffect::RequestCooperativeCancel];
            }
            AppAction::Mounted => self.page = AppPage::Mounted,
            AppAction::MountFailed(message) => {
                self.page = AppPage::Error;
                self.error = Some(AppError {
                    kind: AppErrorKind::Mount,
                    message,
                    recovery: Recovery::OpenUrl("https://winfsp.dev/rel/"),
                });
            }
            AppAction::Unmounted(Ok(())) => self.page = AppPage::Result,
            AppAction::Unmounted(Err(message)) => {
                self.page = AppPage::Error;
                self.error = Some(AppError {
                    kind: AppErrorKind::Mount,
                    message,
                    recovery: Recovery::Close,
                });
            }
        }
        vec![AppEffect::Render]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_map_to_expected_pages() {
        assert_eq!(AppState::new(Route::Help).page, AppPage::Help);
        assert_eq!(
            AppState::new(Route::Container("vault.cfs".into())).page,
            AppPage::Actions
        );
        for form in [
            FormKind::Mount("vault.cfs".into()),
            FormKind::Extract {
                container: "vault.cfs".into(),
                output: "output".into(),
            },
            FormKind::Verify("vault.cfs".into()),
            FormKind::ChangePassword("vault.cfs".into()),
            FormKind::Pack {
                source: "source".into(),
                output: "vault.cfs".into(),
            },
        ] {
            assert_eq!(AppState::new(Route::Form(form)).page, AppPage::Form);
        }
        assert_eq!(
            AppState::new(Route::Pack {
                source: "source".into(),
                output: "vault.cfs".into(),
            })
            .page,
            AppPage::Form
        );
    }

    #[test]
    fn dialog_cancel_is_not_an_error_but_hresult_is_typed() {
        let mut state = AppState::new(Route::Container("vault.cfs".into()));
        state.transition(AppAction::DialogCancelled);
        assert_eq!(state.page, AppPage::Actions);
        state.transition(AppAction::DialogFailed("HRESULT 0x8000FFFF".into()));
        assert_eq!(state.page, AppPage::Error);
        assert_eq!(state.error.unwrap().kind, AppErrorKind::NativeDialog);
    }

    #[test]
    fn cancellation_is_two_stage_and_protected_work_cannot_cancel() {
        let mut state = AppState::new(Route::Form(FormKind::Verify("vault.cfs".into())));
        state.transition(AppAction::OperationStarted);
        assert_eq!(
            state.transition(AppAction::CancelPressed),
            [AppEffect::RequestCooperativeCancel]
        );
        assert_eq!(
            state.transition(AppAction::CancelPressed),
            [AppEffect::ShowForceClose]
        );
        let mut protected = AppState::new(Route::Form(FormKind::Verify("vault.cfs".into())));
        protected.transition(AppAction::OperationStarted);
        protected.transition(AppAction::OperationProtected);
        assert_eq!(
            protected.transition(AppAction::CancelPressed),
            [AppEffect::Render]
        );
    }

    #[test]
    fn operation_and_mount_failures_choose_the_right_recovery() {
        let mut operation = AppState::new(Route::Form(FormKind::Verify("vault.cfs".into())));
        operation.transition(AppAction::OperationFinished(Err("bad password".into())));
        assert_eq!(operation.error.unwrap().recovery, Recovery::Close);

        let mut mount = AppState::new(Route::Form(FormKind::Mount("vault.cfs".into())));
        mount.transition(AppAction::MountFailed("WinFsp unavailable".into()));
        assert_eq!(
            mount.error.unwrap().recovery,
            Recovery::OpenUrl("https://winfsp.dev/rel/")
        );

        let mut completed = AppState::new(Route::Form(FormKind::Verify("vault.cfs".into())));
        completed.transition(AppAction::OperationStarted);
        completed.transition(AppAction::OperationFinished(Ok(())));
        assert_eq!(completed.page, AppPage::Result);

        let mut unmounted = AppState::new(Route::Form(FormKind::Mount("vault.cfs".into())));
        unmounted.transition(AppAction::Mounted);
        assert_eq!(unmounted.page, AppPage::Mounted);
        unmounted.transition(AppAction::Unmounted(Ok(())));
        assert_eq!(unmounted.page, AppPage::Result);
    }
}
