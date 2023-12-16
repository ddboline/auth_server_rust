function post(url = ``, data = {}) {
  // Default options are marked with *
  return fetch(url, {
    method: 'POST', // *GET, POST, PUT, DELETE, etc.
    mode: 'cors', // no-cors, cors, *same-origin
    cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
    },
    redirect: 'follow', // manual, *follow, error
    referrer: 'no-referrer', // no-referrer, *client
    body: JSON.stringify(data), // body data type must match "Content-Type" header
  }).then(response => response.json()); // parses response to JSON
}
function logout() {
  let url = "/api/auth";
  let xmlhttp = new XMLHttpRequest();
  xmlhttp.onload = function() {
      location.reload()
  }
  xmlhttp.open("DELETE", url, true);
  xmlhttp.send(null);
}
function delete_session_data( session_key ) {
  let url = "/api/sessions?session_key=" + session_key;
  let xmlhttp = new XMLHttpRequest();
  xmlhttp.onload = function() {
      list_sessions();
      list_session_data();
  }
  xmlhttp.open("DELETE", url, true);
  xmlhttp.send(null);
}
function delete_session( session_id ) {
  let url = "/api/sessions?session=" + session_id;
  let xmlhttp = new XMLHttpRequest();
  xmlhttp.onload = function() {
      list_sessions();
      list_session_data();
  }
  xmlhttp.open("DELETE", url, true);
  xmlhttp.send(null);
}
function registerViaEmail() {
  let email = document.querySelector('#email');

  var xmlhttp = new XMLHttpRequest();
  xmlhttp.onload = function() {
    email.value = '';
    document.getElementsByClassName("login").innerHTML = "Please check your email.";
  }
  var data = JSON.stringify({"email": email.value});
  xmlhttp.open( "POST", "/api/invitation", true );
  xmlhttp.setRequestHeader("Content-Type", "application/json");
  xmlhttp.send(data);
}
function openIdConnectLogin(final_url) {
  let url = "/api/auth_url";
  if(final_url == null ) {
    final_url = window.location.href;
  }
  let data = JSON.stringify({"final_url": final_url});
  let xmlhttp = new XMLHttpRequest();
  xmlhttp.onload = function() {
    js = JSON.parse(xmlhttp.responseText);

    let xmlhttp2 = new XMLHttpRequest();
    xmlhttp2.onload = function() {
      location.replace(final_url);
    }
    let url2 = "/api/await?state=" + js.csrf_state;
    xmlhttp2.open("GET", url2, true);
    xmlhttp2.send(null);

    window.open(js.auth_url, '_blank');
    window.focus();
  }
  xmlhttp.open("POST", url, true);
  xmlhttp.setRequestHeader("Content-Type", "application/json");
  xmlhttp.send(data);
}
function login(final_url) {
  let email = document.querySelector('#email');
  let password = document.querySelector('#password');
  var data = JSON.stringify({"email": email.value, "password": password.value});
  var xmlhttp = new XMLHttpRequest();
  xmlhttp.onload = function() {
    if(final_url) {
      location.replace(final_url);
    } else {
      location.reload();
    }
  }
  xmlhttp.open( "POST", '/api/auth' , true );
  xmlhttp.setRequestHeader("Content-Type", "application/json");
  xmlhttp.send(data);
}
function sendVerificationEmail() {
  let email = document.querySelector('#email');

  var xmlhttp = new XMLHttpRequest();
  xmlhttp.onload = function() {
    email.value = '';
    document.getElementsByClassName("login").innerHTML = "Please check your email.";
  }
  var data = JSON.stringify({"email": email.value});
  xmlhttp.open( "POST", "/api/password_change", true );
  xmlhttp.setRequestHeader("Content-Type", "application/json");
  xmlhttp.send(data);
}
