// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

function getComments() {
  fetch('/comments').then(response => response.json()).then((json) => {
    const commentsElement = document.getElementById('comments');
    commentsElement.innerText = '';
    const comments = json.comments;
    for (let i = 0; i < comments.length; i++) {
      commentsElement.appendChild(
          createCommentElement(comments[i].userName, comments[i].comment));
    }
  });
}

function createCommentElement(userName, comment) {
  const pElement = document.createElement('p');
  pElement.textContent = comment;
  pElement.setAttribute('class', 'comment');
  const divElement = document.createElement('div');
  divElement.innerText = userName + ': ';
  divElement.appendChild(pElement);
  return divElement;
}

function getLoggedInStatus() {
  fetch('/login-logout').then(response => response.json()).then((json) => {
    if (json.loggedIn) {
      displayElementWithId('login-container', false);
      const pElement = document.getElementById('display-user');
      pElement.textContent = "Logged in as: " + json.userEmail;
      displayElementWithId('display-user', true);
      displayElementWithId('comment-form', true);
      document.getElementById('logout-btn').href = json.logoutUrl;
    } else {
      document.getElementById('login-btn').href = json.loginUrl;
      displayElementWithId('login-container', true);
      displayElementWithId('display-user', false);
      displayElementWithId('comment-form', false);
    }
  });
}


function displayElementWithId(elementId, show) {
  if (show)
    document.getElementById(elementId).style.display = "block";
  else 
    document.getElementById(elementId).style.display = "none";
}