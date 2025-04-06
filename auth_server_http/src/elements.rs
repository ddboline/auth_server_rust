use dioxus::prelude::{Element, IntoDynNode, Props, VirtualDom, component, dioxus_elements, rsx};
use stack_string::{StackString, format_sstr};
use std::fmt::Error;
use time::macros::format_description;
use uuid::Uuid;

#[cfg(debug_assertions)]
use dioxus::prelude::{GlobalSignal, Readable};

use auth_server_lib::{session::SessionSummary, session_data::SessionData};

use crate::logged_user::LoggedUser;

/// # Errors
/// Returns formatting error.
pub fn index_body(
    user: Option<LoggedUser>,
    summaries: Vec<SessionSummary>,
    data: Vec<(SessionData, StackString)>,
    final_url: Option<StackString>,
) -> Result<StackString, Error> {
    let mut app = VirtualDom::new_with_props(
        IndexElement,
        IndexElementProps {
            user,
            summaries,
            data,
            final_url,
        },
    );
    app.rebuild_in_place();
    let mut renderer = dioxus_ssr::Renderer::default();
    let mut buffer = String::new();
    renderer.render_to(&mut buffer, &app)?;
    Ok(buffer.into())
}

#[component]
fn IndexElement(
    user: Option<LoggedUser>,
    summaries: Vec<SessionSummary>,
    data: Vec<(SessionData, StackString)>,
    final_url: Option<StackString>,
) -> Element {
    let login_element = if let Some(user) = &user {
        logged_in_element(&user.email)
    } else {
        index_element(final_url.as_ref().map(Into::into))
    };

    let list_session_data_box = if user.is_none() {
        rsx! {div{ id: "list_session_data_box" }}
    } else {
        rsx! {div{ id: "list_session_data_box", {session_data_element(&data)} }}
    };

    let list_sessions_box = if user.is_none() {
        rsx! { div { id: "list_sessions_box" }}
    } else {
        rsx! { div { id: "list_sessions_box", {session_element(&summaries)} }}
    };

    rsx! {
        {head_element()},
        body {
            {login_element},
            div {
                h2 {
                    a {
                        href: "/api/openapi/json",
                        target: "_blank",
                        "Api Docs"
                    }
                }
            },
            {list_session_data_box},
            div {
                id: "list_session_data_box",
            },
            br {
                {list_sessions_box},
            }
        }
    }
}

fn head_element() -> Element {
    rsx! {
        head {
            title: "Auth App",
            meta {charset: "utf-8"},
            meta {name: "viewport", content: "width=device-width, initial-scale=1"},
            link {
                rel: "stylesheet",
                "type": "text/css",
                media: "screen",
                href: "/auth/main.css",
            },
            script {
                src: "/auth/main.js",
            }
        }
    }
}

fn logged_in_element(email: &str) -> Element {
    rsx! {
        br {
            h1 {
                "Logged in as: {email}"
            }
        }
        input {
            "type": "button",
            name: "logout",
            value: "Logout",
            "onclick": "logout()",
        }
    }
}

fn index_element(final_url: Option<&str>) -> Element {
    let final_url = if let Some(final_url) = final_url {
        format_sstr!("'{final_url}'")
    } else {
        format_sstr!("null")
    };
    rsx! {
        div {
            class: "login",
            input {
                class: "field",
                "type": "text",
                placeholder: "email",
                id: "email",
            },
            input {
                class: "btn",
                "type": "submit",
                value: "Register via Email",
                "onclick": "registerViaEmail()",
            }
            br {
                input {
                    class: "field",
                    "type": "password",
                    placeholder: "Password",
                    id: "password",
                }
                input {
                    class: "btn",
                    "type": "submit",
                    value: "Login",
                    "onclick": "login({final_url})",
                }
            }
            input {
                class: "btn",
                "type": "submit",
                value: "Change Password",
                "onclick": "sendVerificationEmail()",
            }
            br {
                input {
                    class: "btn",
                    "type": "submit",
                    value: "Login via Google Oauth",
                    "onclick": "openIdConnectLogin({final_url})",
                }
            }
        }
    }
}

/// # Errors
/// Returns formatting error.
pub fn register_body(invitation_id: Uuid) -> Result<StackString, Error> {
    let mut app =
        VirtualDom::new_with_props(RegisterElement, RegisterElementProps { invitation_id });
    app.rebuild_in_place();
    let mut renderer = dioxus_ssr::Renderer::default();
    let mut buffer = String::new();
    renderer.render_to(&mut buffer, &app)?;
    Ok(buffer.into())
}

#[component]
fn RegisterElement(invitation_id: Uuid) -> Element {
    rsx! {
        {head_element()},
        body {
            div {
                class: "login",
                h1 {
                    "Register Account"
                },
                p {
                    "Please enter your password"
                },
                input {
                    class: "field",
                    "type": "password",
                    placeholder: "Password",
                    id: "password",
                }
                input {
                    class: "field",
                    "type": "password",
                    placeholder: "Repeat Password",
                    id: "password_repeat",
                }
                input {
                    class: "btn",
                    "type": "submit",
                    value: "Register",
                    "onclick": "register({invitation_id})",
                }
            }
        }
    }
}

fn session_data_element(data: &[(SessionData, StackString)]) -> Element {
    rsx! {
        table {
            "border": "1",
            class: "dataframe",
            thead {
                tr {
                    th {"Session ID"},
                    th {"Session Key"},
                    th {"Created At"},
                    th {"Session Value"},
                }
            },
            tbody {
                {data.iter().enumerate().map(|(idx, (s, js))| {
                    let id = s.session_id;
                    let key = &s.session_key;
                    let created_at = s.created_at.format(format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z")).unwrap_or_else(|_| String::new());
                    rsx! {
                        tr {
                            key: "list-session-data-row-{idx}",
                            style: "text-align",
                            td {"{id}"},
                            td {"{key}"},
                            td {"{created_at}"},
                            td {"{js}"},
                            td {
                                input {
                                    "type": "button",
                                    name: "delete",
                                    value: "Delete",
                                    "onclick": "delete_session_data('{key}')",
                                }
                            }
                        }
                    }
                })},
            }
        }
    }
}

/// # Errors
/// Returns formatting error.
pub fn session_body(summaries: Vec<SessionSummary>) -> Result<StackString, Error> {
    let mut app = VirtualDom::new_with_props(SessionElement, SessionElementProps { summaries });
    app.rebuild_in_place();
    let mut renderer = dioxus_ssr::Renderer::default();
    let mut buffer = String::new();
    renderer.render_to(&mut buffer, &app)?;
    Ok(buffer.into())
}

#[component]
fn SessionElement(summaries: Vec<SessionSummary>) -> Element {
    session_element(&summaries)
}

fn session_element(summaries: &[SessionSummary]) -> Element {
    rsx! {
        table {
            "border": "1",
            class: "dataframe",
            style: "text-align: center",
            thead {
                tr {
                    th {"Session ID"},
                    th {"Email Address"},
                    th {"Created At"},
                    th {"Number of Data Objects"},
                },
            },
            tbody {
                {summaries.iter().enumerate().map(|(idx, s)| {
                    let id = s.session_id;
                    let email = &s.email_address;
                    let created_at = s.created_at.format(format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z")).unwrap_or_else(|_| String::new());
                    let n_obj = s.number_of_data_objects;
                    rsx! {
                        tr {
                            key: "list-session-row-{idx}",
                            style: "text-align: center",
                            td {"{id}"},
                            td {"{email}"},
                            td {"{created_at}"},
                            td {"{n_obj}"},
                            td {
                                input {
                                    "type": "button",
                                    name: "delete",
                                    value: "Delete",
                                    "onclick": "delete_session('{id}')",
                                }
                            }
                        }
                    }
                })},
            }
        }
    }
}

/// # Errors
/// Returns formatting error.
pub fn login_body(
    user: Option<LoggedUser>,
    final_url: Option<StackString>,
) -> Result<StackString, Error> {
    let mut app = VirtualDom::new_with_props(LoginElement, LoginElementProps { user, final_url });
    app.rebuild_in_place();
    let mut renderer = dioxus_ssr::Renderer::default();
    let mut buffer = String::new();
    renderer.render_to(&mut buffer, &app)?;
    Ok(buffer.into())
}

#[component]
fn LoginElement(user: Option<LoggedUser>, final_url: Option<StackString>) -> Element {
    rsx! {
        {head_element()},
        body {
            if let Some(user) = &user {
                {logged_in_element(&user.email)}
            } else {
                {index_element(final_url.as_ref().map(Into::into))}
            }
        }
    }
}

/// # Errors
/// Returns formatting error.
pub fn change_password_body(user: LoggedUser) -> Result<StackString, Error> {
    let mut app =
        VirtualDom::new_with_props(ChangePasswordElement, ChangePasswordElementProps { user });
    app.rebuild_in_place();
    let mut renderer = dioxus_ssr::Renderer::default();
    let mut buffer = String::new();
    renderer.render_to(&mut buffer, &app)?;
    Ok(buffer.into())
}

#[component]
fn ChangePasswordElement(user: LoggedUser) -> Element {
    let email = &user.email;

    rsx! {
        {head_element()},
        body {
            div {
                class: "login",
                h1 {
                    "Change Password",
                },
                p {
                    "Enter your old password, new password",
                }
                input {
                    class: "field",
                    "type": "password",
                    placeholder: "Old Password",
                    id: "old_password",
                },
                input {
                    class: "field",
                    "type": "password",
                    placeholder: "New Password",
                    id: "new_password",
                },
                input {
                    class: "field",
                    "type": "password",
                    placeholder: "Repeat New Password",
                    id: "new_password_repeat",
                },
                input {
                    class: "btn",
                    "type": "submit",
                    value: "Change Password",
                    "onclick": "password_change('{email}')"
                },
            }
        }
    }
}

/// # Errors
/// Returns formatting error.
pub fn session_data_body(data: Vec<(SessionData, StackString)>) -> Result<StackString, Error> {
    let mut app = VirtualDom::new_with_props(SessionDataElement, SessionDataElementProps { data });
    app.rebuild_in_place();
    let mut renderer = dioxus_ssr::Renderer::default();
    let mut buffer = String::new();
    renderer.render_to(&mut buffer, &app)?;
    Ok(buffer.into())
}

#[component]
fn SessionDataElement(data: Vec<(SessionData, StackString)>) -> Element {
    session_data_element(&data)
}
