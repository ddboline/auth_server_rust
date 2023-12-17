use dioxus::prelude::{
    component, dioxus_elements, rsx, Element, GlobalAttributes, IntoDynNode, LazyNodes, Props,
    Scope,
};
use stack_string::{StackString, format_sstr};
use uuid::Uuid;
use time::macros::format_description;

use auth_server_lib::session::SessionSummary;
use auth_server_lib::session_data::SessionData;

use crate::logged_user::LoggedUser;

#[component]
pub fn IndexElement(
    cx: Scope,
    user: Option<LoggedUser>,
    summaries: Vec<SessionSummary>,
    data: Vec<(SessionData, StackString)>,
    final_url: Option<StackString>,
) -> Element {
    let login_element = if let Some(user) = user {
        logged_in_element(&user.email)
    } else {
        index_element(final_url.as_ref().map(Into::into))
    };

    let list_session_data_box = if user.is_none() {
        rsx! {div{ id: "list_session_data_box" }}
    } else {
        rsx! {div{ id: "list_session_data_box", session_data_element(&data) }}
    };

    let list_sessions_box = if user.is_none() {
        rsx! { div { id: "list_sessions_box" }}
    } else {
        rsx! { div { id: "list_sessions_box", session_element(&summaries) }}
    };

    cx.render(rsx! {
        head_element(),
        body {
            login_element,
            div {
                h2 {
                    a {
                        href: "/api/openapi/json",
                        target: "_blank",
                        "Api Docs"
                    }
                }
            },
            list_session_data_box,
            div {
                id: "list_session_data_box",
            },
            br {
                list_sessions_box,
            }
        }
    })
}

fn head_element<'a>() -> LazyNodes<'a, 'a> {
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

fn logged_in_element(email: &str) -> LazyNodes {
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

fn index_element(final_url: Option<&str>) -> LazyNodes {
    let final_url = if let Some(final_url) = final_url {
        format_sstr!("\"{final_url}\"")
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

#[component]
pub fn RegisterElement(cx: Scope, invitation_id: Uuid) -> Element {
    let register_fn = format_sstr!(
        "
            function register() {{
                let password = document.querySelector('#password');
                let password_repeat = document.querySelector('#password_repeat');
                if (password.value == password_repeat.value) {{
                    post('/api/register/{invitation_id}', {{password: password.value}}).then(
                        data => {{
                            password.value = '';
                            document.getElementsByClassName('login').innerHTML = data;
                        }}
                    );
                }} else {{
                    console.err('Passwords do not match!');
                }}
            }}
        "
    );
    cx.render(rsx! {
        head_element(),
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
                    "onclick": "register()",
                }
            }
            script {
                dangerous_inner_html: "{register_fn}",
            }
        }
    })
}

fn session_data_element(data: &[(SessionData, StackString)]) -> LazyNodes {
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
                data.iter().enumerate().map(|(idx, (s, js))| {
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
                }),
            }
        }
    }
}

#[component]
pub fn SessionElement(cx: Scope, summaries: Vec<SessionSummary>) -> Element {
    cx.render(session_element(summaries))
}

fn session_element(summaries: &[SessionSummary]) -> LazyNodes {
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
                summaries.iter().enumerate().map(|(idx, s)| {
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
                }),
            }
        }
    }
}

#[component]
pub fn LoginElement(cx: Scope, user: Option<LoggedUser>, final_url: Option<StackString>) -> Element {
    cx.render(rsx! {
        head_element(),
        body {
            if let Some(user) = &user {
                logged_in_element(&user.email)
            } else {
                index_element(final_url.as_ref().map(Into::into))
            }
        }
    })
}

#[component]
pub fn ChangePasswordElement(cx: Scope, user: LoggedUser) -> Element {
    let email = &user.email;
    let password_change_fn = format_sstr!(
        "
            function password_change() {{
                let password = document.querySelector('#old_password');
                var data = JSON.stringify(
                    {{
                        \"email\": \"{email}\",
                        \"password\": password.value
                    }}
                );
                var xmlhttp = new XMLHttpRequest();
                xmlhttp.onload = function() {{
                   password_change()
                }}
                xmlhttp.open( \"POST\", '/api/auth' , true );
                xmlhttp.setRequestHeader(\"Content-Type\", \"application/json\");
                xmlhttp.send(data);
            }}
            function change_password_fn() {{
                let password = document.querySelector('#new_password');
                let password_repeat = document.querySelector('#new_password_repeat');
                if (password.value == password_repeat.value) {{
                        post(
                            '/api/password_change', {{
                                password: password.value
                            }}).then(
                                data => {{
                                password.value = '';
                                document.getElementsByClassName(\"login\").innerHTML = data;
                            }}
                        );
                }} else {{
                  console.err('Passwords do not match!');
                }}
            }}
        "
    );

    cx.render(rsx! {
        head_element(),
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
                    "onclick": "password_change()"
                },
            }
            script {
                dangerous_inner_html: "{password_change_fn}",
            }
        }
    })
}

#[component]
pub fn SessionDataElement(cx: Scope, data: Vec<(SessionData, StackString)>) -> Element {
    cx.render(session_data_element(data))
}