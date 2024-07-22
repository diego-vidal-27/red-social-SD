let mediaRecorder;
let audioChunks = [];

export function initAudioRecorder(audioButton, socket, token, contactId) {
    audioButton.removeEventListener('mousedown', startRecording);
    audioButton.removeEventListener('mouseup', stopRecording);

    audioButton.addEventListener('mousedown', startRecording);
    audioButton.addEventListener('mouseup', stopRecording);

    async function startRecording() {
        console.log("Start recording triggered");
        if (!mediaRecorder) {
            const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            mediaRecorder = new MediaRecorder(stream);
            mediaRecorder.ondataavailable = (event) => {
                console.log("Data available event triggered");
                audioChunks.push(event.data);
            };
            mediaRecorder.onstop = async () => {
                console.log("MediaRecorder stopped");
                if (audioChunks.length > 0) {
                    const audioBlob = new Blob(audioChunks, { type: 'audio/mp3' });
                    audioChunks = [];  

                    const formData = new FormData();
                    formData.append('file', audioBlob, 'audio.mp3');

                    const response = await fetch('/upload', {
                        method: 'POST',
                        body: formData,
                        headers: {
                            'x-access-token': token
                        }
                    });

                    const result = await response.json();
                    if (response.status === 200) {
                        const fileData = result.file;
                        console.log("File uploaded successfully");
                        socket.emit('chat message', { msg: '', file: fileData, userId: localStorage.getItem('userId'), contactId });
                    } else {
                        console.error('Error uploading file:', result.message);
                        alert('Error al subir el archivo: ' + result.message);
                    }
                }
            };
        }
        mediaRecorder.start();
        console.log("MediaRecorder started");
        audioButton.classList.add('recording');
    }

    function stopRecording() {
        console.log("Stop recording triggered");
        if (mediaRecorder && mediaRecorder.state !== 'inactive') {
            mediaRecorder.stop();
            audioButton.classList.remove('recording');
        }
    }
}
