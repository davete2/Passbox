$('#password-generator').submit(function (event) {
    event.preventDefault();

    let lenght = $('#lenght').val();
    let nums = $('#nums').val();
    let special = $('#special').val();
    let password = generatePassword(lenght, nums, special);
    console.log(password)
    $('#generated-password').val(password)
});

function generatePassword(lenght, nums, special) {
    let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let numbers = "0123456789";
    let symbols = "!@#$%^&*()_-+=<>?";

    let password;

    letters = shuffle(letters);
    numbers = shuffle(numbers);
    symbols = shuffle(symbols);


    letters = letters.substring(0, lenght - nums - special);
    numbers = numbers.substring(0, nums);
    symbols = symbols.substring(0, special);


    password = letters + numbers + symbols;
    password = shuffle(password);
    return password;

}

function getRandomInt(n) {
    return Math.floor(Math.random() * n);
}

function shuffle(s) {
    let arr = s.split('');
    let n = arr.length;

    for (let i = 0; i < n - 1; ++i) {
        let j = getRandomInt(n);

        let temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }

    s = arr.join('');
    return s;
}


$(document).ready(function () {
    let lenght = $('#lenght').val();
    let nums = $('#nums').val();
    let special = $('#special').val();
    let password = generatePassword(lenght, nums, special);

    $('#generated-password').val(password)
})

function create() {
    var email = document.getElementById("emailAggiungi")
    var password = document.getElementById("passwordAggiungi");
    var url = document.getElementById("urlAggiungi");
    var titolo = document.getElementById("titoloAggiungi");
    var note = document.getElementById("noteAggiungi");

    var encryptedPassword = CryptoJS.AES.encrypt(password.value, "SecretKey").toString();

    var cred = {
        email: email.value,
        password: encryptedPassword,
        url: url.value,
        titolo: titolo.value,
        note: note.value,
    }
    fetch(`${window.origin}/password_vault/create`, {
        method: "POST",
        credentials: "include",
        body: JSON.stringify(cred),
        cache: "no-cache",
        headers: new Headers({
            "content-type": "application/json"
        })
    }).then(function (response) {
        window.location.reload();
    }).catch(function (error) {
        console.error("Error during fetch operation:", error);
    });
}

$(document).ready(function decryptCredentials() {
    var encryptedPassword = document.getElementById("pwdUpdate")
    var decryptedPassword = CryptoJS.AES.decrypt(encryptedPassword.value, "SecretKey").toString(CryptoJS.enc.Utf8);
    $('#pwdUpdate').val(decryptedPassword)

})

$(document).ready(function decryptGroupCredentials() {
    var encryptedPassword = document.getElementById("pwdGroupUpdate")
    var decryptedPassword = CryptoJS.AES.decrypt(encryptedPassword.value, "SecretKey").toString(CryptoJS.enc.Utf8);
    $('#pwdGroupUpdate').val(decryptedPassword)

})

$('#form-password-update').submit(function (event) {
    event.preventDefault();


    var email = document.getElementById("emailUpdate")
    var password = document.getElementById("pwdUpdate");
    var url = document.getElementById("urlUpdate");
    var titolo = document.getElementById("titoloUpdate");
    var id = document.getElementById("password-id");
    var note = document.getElementById("noteUpdate");

    var encryptedPassword = CryptoJS.AES.encrypt(password.value, "SecretKey").toString();

    var cred = {
        email: email.value,
        password: encryptedPassword,
        url: url.value,
        titolo: titolo.value,
        note: note.value,
        id: id.value
    }

    var res = fetch(`${window.origin}/password/update`, {
        method: "POST",
        credentials: "include",
        body: JSON.stringify(cred),
        cache: "no-cache",
        headers: new Headers({
            "content-type": "application/json"
        })
    }).then(function (response) {
        window.location.href = `${window.origin}/password/${id.value}`;
    }).catch(function (error) {
        console.error("Error during fetch operation:", error);
    });

});

$('#form-group-password-update').submit(function (event) {
    event.preventDefault();

    var email = document.getElementById("emailGroupUpdate")
    var password = document.getElementById("pwdGroupUpdate");
    var url = document.getElementById("urlGroupUpdate");
    var titolo = document.getElementById("titoloGroupUpdate");
    var id = document.getElementById("password-group-id");
    var note = document.getElementById("noteGroupUpdate");

    var encryptedPassword = CryptoJS.AES.encrypt(password.value, "SecretKey").toString();

    var cred = {
        email: email.value,
        password: encryptedPassword,
        url: url.value,
        titolo: titolo.value,
        note: note.value,
        id: id.value
    }


    var res = fetch(`${window.origin}/group_vault/group_password/update`, {
        method: "POST",
        credentials: "include",
        body: JSON.stringify(cred),
        cache: "no-cache",
        headers: new Headers({
            "content-type": "application/json"
        })
    }).then(function (response) {
        window.location.href = `${window.origin}/group_vault/group_password/${id.value}`;
    }).catch(function (error) {
        console.error("Error during fetch operation:", error);
    });

});

function decryptCredentialsToCopy(pass) {
    return decryptedPasswordToCopy = CryptoJS.AES.decrypt(pass, "SecretKey").toString(CryptoJS.enc.Utf8);
}

function copyPassToClipboard() {
    pass = document.getElementById("pwdUpdate")
    console.log(pass.value)
    navigator.clipboard.writeText(pass.value);
}

function copyGeneratedPass() {
    pass = document.getElementById("generated-password")
    console.log(pass.value)
    navigator.clipboard.writeText(pass.value);
}


function copyEmailToClipboard() {
    email = document.getElementById("emailUpdate");
    console.log(email.value)
    navigator.clipboard.writeText(email.value);
}

$(".reveal").on("click", function () {
    var $pwd = $(".pwd");
    if ($pwd.attr("type") === "password") {
        $pwd.attr("type", "text");
    } else {
        $pwd.attr("type", "password");
    }

})

$(".deleteMembers").on("click", function () {
    window.location.reload();
})

function createGroupCredentials() {
    var email = document.getElementById("emailPassGruppo")
    var password = document.getElementById("passwordPassGruppo");
    var url = document.getElementById("urlPassGruppo");
    var titolo = document.getElementById("titoloPassGruppo");
    var note = document.getElementById("notePassGruppo");
    var group_id = document.getElementById("groupId")
    var encryptedPassword = CryptoJS.AES.encrypt(password.value, "SecretKey").toString();

    var cred = {
        email: email.value,
        password: encryptedPassword,
        url: url.value,
        titolo: titolo.value,
        note: note.value,
    }
    fetch(`${window.origin}/group_vault/createGroupCredentials/${group_id.value}`, {
            method: "POST",
            credentials: "include",
            body: JSON.stringify(cred),
            cache: "no-cache",
            headers: new Headers({
                "content-type": "application/json"
            })
        }
    ).then(function (response) {
        window.location.reload();
    }).catch(function (error) {
        console.error("Error during fetch operation:", error);
    });
}


var type;

$(".payBusiness").on("click", function () {
    type = "business"
})

$(".payPremium").on("click", function () {
    type = "premium"
})


paypal.Buttons({

    style: {
        layout: 'vertical',
        background: 'black',
        shape: 'rect',
        label: 'paypal'
    },

    createOrder: function (data, actions) {
        return fetch('/create-order', {
            method: "POST",
            headers: {
                "Content-Type": 'application/json'
            },
            body: JSON.stringify({
                item: [
                    {
                        type: type,
                    },
                ],
            }),
        }).then(res => {
            if (res.ok) return res.json()
            return res.json().then(json => Promise.reject(json))
        }).then(({ id }) => {
            return id
        }).catch(e => {
            console.error((e.error))
        })
    },
    onApprove: function (data, actions) {
        return actions.order.capture().then(function (details) {
            alert(("Transaction completed"))
        })
    },
}).render('#paypal-button-container')

var paypalButtons = $("#paypal-button-container")
$(".pay").on("click", function () {
    paypalButtons.toggleClass('is-open')
})