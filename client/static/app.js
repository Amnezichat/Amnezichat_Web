const qid = (id) => document.getElementById(id);

let profilePicBase64 = localStorage.getItem("profilePic") || "";
const notifiedMessageSet = new Set(JSON.parse(localStorage.getItem("notifiedMessages") || "[]"));
let mediaRecorder = null;
let audioChunks = [];
let recordingStartTime = null;
let recordingTimerInterval = null;
let notificationsEnabled = localStorage.getItem("notificationsEnabled") !== "false";
let autosaveEnabled = localStorage.getItem("autosaveEnabled") !== "false";
let messageRefreshInterval = null;
let lastMessageCount = 0;

const getStoredMessages = () =>
  autosaveEnabled ? JSON.parse(localStorage.getItem("cachedMessages") || "[]") : [];

const storeMessages = (messages) => {
  if (autosaveEnabled) {
    localStorage.setItem("cachedMessages", JSON.stringify(messages));
  }
};

const hashMessage = (message) => message.replace(/<[^>]*>/g, "").trim();

const showToast = (message, type = 'info') => {
  const toast = qid("toast");
  const toastMessage = toast.querySelector(".toast-message");
  
  toastMessage.textContent = message;
  toast.classList.remove("hidden");
  
  setTimeout(() => {
    toast.classList.add("show");
  }, 10);
  
  setTimeout(() => {
    hideToast();
  }, 3000);
};

const hideToast = () => {
  const toast = qid("toast");
  toast.classList.remove("show");
  setTimeout(() => {
    toast.classList.add("hidden");
  }, 300);
};

const showNotification = (message) => {
  if (!notificationsEnabled) return;
  
  const messageHash = hashMessage(message);
  if (!notifiedMessageSet.has(messageHash) && Notification.permission === "granted") {
    new Notification("New Message", { 
      body: messageHash,
      icon: "/static/icon.png",
      tag: "amnezichat-message"
    });
    notifiedMessageSet.add(messageHash);
    if (autosaveEnabled) {
      localStorage.setItem("notifiedMessages", JSON.stringify(Array.from(notifiedMessageSet)));
    }
  }
};

const requestNotificationPermission = async () => {
  if (notificationsEnabled && "Notification" in window) {
    if (Notification.permission === "default") {
      const permission = await Notification.requestPermission();
      if (permission === "granted") {
        showToast("Notifications enabled successfully!");
      }
    }
  }
};

const toggleSidebar = () => {
  const sidebar = qid("sidebar");
  const overlay = qid("sidebarOverlay");
  
  if (sidebar.classList.contains("open")) {
    closeSidebar();
  } else {
    openSidebar();
  }
};

const openSidebar = () => {
  const sidebar = qid("sidebar");
  const overlay = qid("sidebarOverlay");
  
  sidebar.classList.add("open");
  overlay.classList.add("active");
  document.body.style.overflow = "hidden";
};

const closeSidebar = () => {
  const sidebar = qid("sidebar");
  const overlay = qid("sidebarOverlay");
  
  sidebar.classList.remove("open");
  overlay.classList.remove("active");
  document.body.style.overflow = "";
};

const updateThemeIndicators = (theme) => {
  document.querySelectorAll(".theme-option").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.theme === theme);
  });
};

const setTheme = (theme) => {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("theme", theme);
  
  updateThemeIndicators(theme);
  
  document.body.style.transition = "all 0.3s ease";
  showToast(`Theme changed to ${theme}`);
};

const detectSystemTheme = () => {
  if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
    return 'dark';
  }
  return 'light';
};

const initializeTheme = () => {
  const savedTheme = localStorage.getItem("theme") || "dark";
  setTheme(savedTheme);
  
  if (window.matchMedia) {
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
      const currentTheme = localStorage.getItem("theme");
      if (currentTheme === 'auto') {
        updateThemeIndicators('auto');
      }
    });
  }
};

const updateFontSizeIndicators = (size) => {
  document.querySelectorAll(".font-option").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.size === size);
  });
};

const setFontSize = (size) => {
  document.body.className = document.body.className.replace(/font-\w+/g, "");
  document.body.classList.add(`font-${size}`);
  localStorage.setItem("fontSize", size);
  
  updateFontSizeIndicators(size);
};

const toggleNotifications = () => {
  notificationsEnabled = qid("notificationsToggle").checked;
  localStorage.setItem("notificationsEnabled", notificationsEnabled);
  
  if (notificationsEnabled) {
    requestNotificationPermission();
  } else {
    showToast("Notifications disabled");
  }
};

const toggleAutosave = () => {
  autosaveEnabled = qid("autosaveToggle").checked;
  localStorage.setItem("autosaveEnabled", autosaveEnabled);
  
  if (!autosaveEnabled) {
    localStorage.removeItem("cachedMessages");
    localStorage.removeItem("notifiedMessages");
    showToast("Auto-save disabled and data cleared");
  } else {
    showToast("Auto-save enabled");
  }
};

const handleProfilePicChange = (event) => {
  const file = event.target.files[0];
  if (!file) return;

  if (file.size > 5 * 1024 * 1024) {
    showToast("Image too large. Please select an image under 5mb.", "error");
    return;
  }

  const reader = new FileReader();
  reader.onloadend = () => {
    profilePicBase64 = reader.result;
    localStorage.setItem("profilePic", profilePicBase64);
    qid("profilePreview").src = profilePicBase64;
    showToast("Profile picture updated!");
  };
  reader.readAsDataURL(file);
};

const handleWallpaperChange = (event) => {
  const file = event.target.files[0];
  if (!file || !file.type.startsWith('image/')) return;

  if (file.size > 10 * 1024 * 1024) {
    showToast("Image too large. Please select an image under 10MB.", "error");
    return;
  }

  const reader = new FileReader();
  reader.onload = (e) => {
    const imageUrl = e.target.result;
    document.body.style.backgroundImage = `url(${imageUrl})`;
    document.body.style.backgroundSize = 'cover';
    document.body.style.backgroundPosition = 'center';
    document.body.style.backgroundAttachment = 'fixed';
    localStorage.setItem('customWallpaper', imageUrl);
    showToast("Background updated!");
  };
  reader.readAsDataURL(file);
};

const handleMediaChange = (event) => {
  const file = event.target.files[0];
  if (!file) return;

  if (file.size > 25 * 1024 * 1024) {
    showToast("File too large. Please select a file under 25MB.", "error");
    return;
  }

  const reader = new FileReader();
  reader.onloadend = async () => {
    try {
      const mediaBase64 = DOMPurify.sanitize(reader.result);
      const message = `<pfp>${profilePicBase64}</pfp><media>${mediaBase64}</media>`;
      
      const response = await fetch("/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message }),
      });

      if (response.ok) {
        fetchMessages();
        showToast("Media sent successfully!");
      } else {
        throw new Error("Failed to send media");
      }
    } catch (error) {
      showToast("Failed to send media. Please try again.", "error");
    }
  };
  reader.readAsDataURL(file);
};

const fetchMessages = async () => {
  try {
    const res = await fetch("/messages");
    if (!res.ok) throw new Error("Network response was not ok");
    
    const newMessages = await res.json();
    const storedMessages = getStoredMessages();

    if (newMessages.length > lastMessageCount) {
      const messagesToAdd = newMessages.slice(lastMessageCount);
      const combinedMessages = [...storedMessages, ...messagesToAdd];
      
      storeMessages(combinedMessages);
      renderMessages(combinedMessages);
      lastMessageCount = newMessages.length;
    } else if (storedMessages.length === 0) {
      storeMessages(newMessages);
      renderMessages(newMessages);
      lastMessageCount = newMessages.length;
    }
    
    updateConnectionStatus(true);
  } catch (error) {
    console.warn("Fetch failed, loading from local cache.");
    const storedMessages = getStoredMessages();
    renderMessages(storedMessages);
    updateConnectionStatus(false);
  }
};

const updateConnectionStatus = (isOnline) => {
  const statusDot = document.querySelector(".status-dot");
  const statusText = document.querySelector(".status-text");
  
  if (isOnline) {
    statusDot.className = "status-dot online";
    if (statusText) statusText.textContent = "Online";
  } else {
    statusDot.className = "status-dot offline";
    if (statusText) statusText.textContent = "Offline";
  }
};

const renderMessages = (messages) => {
  const messagesDiv = qid("messages");
  const placeholder = qid("messagesPlaceholder");

  if (messages.length === 0) {
    placeholder.classList.remove("hidden");
    messagesDiv.innerHTML = "";
    return;
  }

  placeholder.classList.add("hidden");

  const base64Img = /^data:image\/(png|jpeg|jpg|gif|svg\+xml);base64,/;
  const base64Vid = /^data:video\/(mp4|webm|ogg);base64,/;
  const base64Audio = /^data:audio\/(webm|ogg|mp3);base64,/;

  const messagesHTML = messages
    .map((msg) => {
      const pfpMatch = msg.match(/<pfp>(.*?)<\/pfp>/);
      const mediaMatch = msg.match(/<media>(.*?)<\/media>/);
      const audioMatch = msg.match(/<audio>(.*?)<\/audio>/);

      const messageTextRaw = msg
        .replace(/<pfp>.*?<\/pfp>/, "")
        .replace(/<media>.*?<\/media>/, "")
        .replace(/<audio>.*?<\/audio>/, "")
        .trim();

      const messageText = DOMPurify.sanitize(messageTextRaw);

      const profilePicSrc =
        pfpMatch && base64Img.test(pfpMatch[1])
          ? DOMPurify.sanitize(pfpMatch[1])
          : "/static/default_pfp.jpg";

      const profilePic = `<img src="${profilePicSrc}" class="profile-pic" alt="Profile Picture" loading="lazy">`;
// Quick "fix" for now so I can push my changes, but I need to fetch the username and change from checking pfp, to checking username:
      const isOwnMessage = pfpMatch && pfpMatch[1] === profilePicBase64;
      const messageClass = isOwnMessage ? "own-message" : "other-message";

      let media = "";
      if (mediaMatch) {
        const src = DOMPurify.sanitize(mediaMatch[1]);
        if (base64Img.test(src)) {
          media = `<img src="${src}" class="media-img" alt="Media" onclick="openMediaModal('${src}', false)" loading="lazy">`;
        } else if (base64Vid.test(src)) {
          media = `<video class="media-video" controls preload="metadata" onclick="openMediaModal('${src}', true)"><source src="${src}" type="video/mp4">Your browser does not support video.</video>`;
        }
      }

      if (audioMatch) {
        const src = DOMPurify.sanitize(audioMatch[1]);
        media = `<audio controls class="media-audio" preload="metadata"><source src="${src}" type="audio/webm">Your browser does not support the audio element.</audio>`;
      }

      showNotification(messageText || "New media message");

      return `
        <div class="message-row ${messageClass}">
          ${profilePic}
          <div class="message-bubble">
            ${messageText ? `<p>${messageText}</p>` : ""}
            ${media}
          </div>
        </div>`;
    })
    .join("");

  messagesDiv.innerHTML = DOMPurify.sanitize(messagesHTML, {
    SAFE_FOR_JQUERY: true,
    ADD_ATTR: ["onclick", "loading", "preload"],
  });

  messagesDiv.scrollTo({ top: messagesDiv.scrollHeight, behavior: "smooth" });
};

const sendMessage = async () => {
  const input = qid("messageInput");
  const msg = input.value.trim();
  if (!msg) return;

  if (msg.length > 1000) {
    showToast("Message too long. Please keep it under 1000 characters.", "error");
    return;
  }

  const sanitizedMsg = DOMPurify.sanitize(msg, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
  const message = `<pfp>${profilePicBase64}</pfp>${sanitizedMsg}`;

  input.value = "";

  try {
    const response = await fetch("/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });

    if (response.ok) {
      fetchMessages();
    } else {
      throw new Error("Failed to send message");
    }
  } catch (error) {
    showToast("Failed to send message. Please try again.", "error");
    input.value = sanitizedMsg;
  }
};

const clearCache = () => {
  if (confirm("Are you sure you want to clear all data? This action cannot be undone.")) {
    localStorage.clear();
    
    profilePicBase64 = "";
    notifiedMessageSet.clear();
    audioChunks = [];
    recordingStartTime = null;
    lastMessageCount = 0;
    clearInterval(recordingTimerInterval);
    recordingTimerInterval = null;

    qid("messages").innerHTML = "";
    qid("messageInput").value = "";
    qid("profilePreview").src = "/static/default_pfp.jpg";
    document.body.style.backgroundImage = "";

    const micBtn = qid("micButton");
    micBtn.innerHTML = `
      <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11a7 7 0 01-7 7m0 0a7 7 0 01-7-7m7 7v4m0 0H8m4 0h4m-4-8a3 3 0 01-3-3V5a3 3 0 116 0v6a3 3 0 01-3 3z"></path>
      </svg>
    `;
    micBtn.onclick = startVoiceRecording;

    hideRecordingStatus();
    qid("recordingTime").textContent = "00:00";
    closeSidebar();
    
    setTheme("dark");
    setFontSize("medium");
    qid("notificationsToggle").checked = true;
    qid("autosaveToggle").checked = true;
    notificationsEnabled = true;
    autosaveEnabled = true;
    
    showToast("All data cleared successfully!");
  }
};

const openMediaModal = (src, isVideo = false) => {
  const modal = qid("mediaModal");
  const content = modal.querySelector(".modal-content");
  
  const closeBtn = content.querySelector(".modal-close");
  content.innerHTML = "";
  content.appendChild(closeBtn);

  if (isVideo) {
    const video = document.createElement("video");
    video.controls = true;
    video.src = src;
    video.autoplay = true;
    content.appendChild(video);
  } else {
    const img = document.createElement("img");
    img.src = src;
    img.alt = "Full size media";
    content.appendChild(img);
  }

  modal.classList.add("active");
  document.body.style.overflow = "hidden";
};

const closeMediaModal = () => {
  const modal = qid("mediaModal");
  modal.classList.remove("active");
  document.body.style.overflow = "";
};

const showRecordingStatus = () => {
  const el = qid("recordingStatus");
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("show"), 10);
};

const hideRecordingStatus = () => {
  const el = qid("recordingStatus");
  el.classList.remove("show");
  setTimeout(() => el.classList.add("hidden"), 300);
};

const startVoiceRecording = async () => {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ 
      audio: { 
        echoCancellation: true,
        noiseSuppression: true,
        sampleRate: 44100
      } 
    });
    
    mediaRecorder = new MediaRecorder(stream, {
      mimeType: 'audio/webm;codecs=opus'
    });
    audioChunks = [];
    recordingStartTime = Date.now();

    mediaRecorder.ondataavailable = (event) => {
      if (event.data.size > 0) {
        audioChunks.push(event.data);
      }
    };

    mediaRecorder.onstop = async () => {
      clearInterval(recordingTimerInterval);
      hideRecordingStatus();
      
      stream.getTracks().forEach(track => track.stop());

      if (!audioChunks.length) return;

      const audioBlob = new Blob(audioChunks, { type: "audio/webm" });
      const reader = new FileReader();
      reader.onloadend = async () => {
        try {
          const audioBase64 = DOMPurify.sanitize(reader.result);
          const message = `<pfp>${profilePicBase64}</pfp><audio>${audioBase64}</audio>`;
          
          const response = await fetch("/send", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message }),
          });

          if (response.ok) {
            fetchMessages();
            showToast("Voice message sent!");
          } else {
            throw new Error("Failed to send voice message");
          }
        } catch (error) {
          showToast("Failed to send voice message. Please try again.", "error");
        }
      };
      reader.readAsDataURL(audioBlob);
    };

    mediaRecorder.start();
    startTimer();

    const micBtn = qid("micButton");
    micBtn.innerHTML = `
      <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <rect x="9" y="9" width="6" height="6"></rect>
        <path d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
      </svg>
    `;
    micBtn.onclick = stopVoiceRecording;

    showRecordingStatus();
  } catch (err) {
    showToast("Microphone access denied or not available.", "error");
    console.error(err);
  }
};

const stopVoiceRecording = () => {
  if (mediaRecorder && mediaRecorder.state === "recording") {
    mediaRecorder.stop();
  }
  resetMicButton();
};

const cancelVoiceRecording = () => {
  if (mediaRecorder && mediaRecorder.state !== "inactive") {
    mediaRecorder.stop();
  }
  audioChunks = [];
  clearInterval(recordingTimerInterval);
  hideRecordingStatus();
  resetMicButton();
  showToast("Recording cancelled");
};

const resetMicButton = () => {
  const micBtn = qid("micButton");
  micBtn.innerHTML = `
    <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11a7 7 0 01-7 7m0 0a7 7 0 01-7-7m7 7v4m0 0H8m4 0h4m-4-8a3 3 0 01-3-3V5a3 3 0 116 0v6a3 3 0 01-3 3z"></path>
    </svg>
  `;
  micBtn.onclick = startVoiceRecording;
};

const startTimer = () => {
  const timerElement = qid("recordingTime");
  recordingTimerInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - recordingStartTime) / 1000);
    const minutes = String(Math.floor(elapsed / 60)).padStart(2, "0");
    const seconds = String(elapsed % 60).padStart(2, "0");

    timerElement.textContent = `${minutes}:${seconds}`;

    if (elapsed >= 300) {
      cancelVoiceRecording();
      showToast("Maximum recording time reached (5 minutes)", "warning");
    }
  }, 1000);
};

const isAudioPlaying = () => {
  return Array.from(document.querySelectorAll("audio")).some(
    (audio) => !audio.paused && !audio.ended
  );
};

const startMessageRefresh = () => {
  if (messageRefreshInterval) {
    clearInterval(messageRefreshInterval);
  }
  
  messageRefreshInterval = setInterval(() => {
    if (!isAudioPlaying() && !document.hidden) {
      fetchMessages();
    }
  }, 5000);
}

const stopMessageRefresh = () => {
  if (messageRefreshInterval) {
    clearInterval(messageRefreshInterval);
    messageRefreshInterval = null;
  }
};

document.addEventListener("DOMContentLoaded", () => {
  initializeTheme();
  
  const savedFontSize = localStorage.getItem("fontSize") || "medium";
  const savedWallpaper = localStorage.getItem('customWallpaper');
  const savedPic = localStorage.getItem("profilePic");
  
  setFontSize(savedFontSize);
  
  if (savedWallpaper) {
    document.body.style.backgroundImage = `url(${savedWallpaper})`;
    document.body.style.backgroundSize = 'cover';
    document.body.style.backgroundPosition = 'center';
    document.body.style.backgroundAttachment = 'fixed';
  }
  
  if (savedPic) {
    profilePicBase64 = savedPic;
    qid("profilePreview").src = savedPic;
  }
  
  qid("notificationsToggle").checked = notificationsEnabled;
  qid("autosaveToggle").checked = autosaveEnabled;

  qid("messageInput").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      sendMessage();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeSidebar();
      closeMediaModal();
      hideToast();
    }
  });

  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      stopMessageRefresh();
    } else {
      startMessageRefresh();
      fetchMessages();
    }
  });

  requestNotificationPermission();
  renderMessages(getStoredMessages());
  fetchMessages();
  startMessageRefresh();
});

window.addEventListener("beforeunload", () => {
  stopMessageRefresh();
  if (!autosaveEnabled) {
    localStorage.removeItem("cachedMessages");
    localStorage.removeItem("notifiedMessages");
  }
});