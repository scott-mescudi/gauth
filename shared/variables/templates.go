package variables

// SignupTemplate
var SignupTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Signup Confirmation</title>
</head>
<body>
    <h2>Welcome to Our Platform!</h2>
    <p>Thank you for signing up! Please click the link below to confirm your email address:</p>
    <a href="{{.Link}}">Confirm your email</a>
</body>
</html>
`

// UpdatePasswordTemplate
var UpdatePasswordTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Update Password</title>
</head>
<body>
    <h2>Update Your Password</h2>
    <p>To reset your password, please click the link below:</p>
    <a href="{{.Link}}">Reset your password</a>
</body>
</html>
`

// UpdateEmailTemplate
var UpdateEmailTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Update Email</title>
</head>
<body>
    <h2>Email Update Confirmation</h2>
    <p>We received a request to update your email address. If you made this request, please confirm by clicking the link below:</p>
    <a href="{{.Link}}">Confirm email update</a>
</body>
</html>
`

// CancelUpdateEmailTemplate
var CancelUpdateEmailTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Cancel Email Update</title>
</head>
<body>
    <h2>Email Update Cancelation</h2>
    <p>If you did not request an email update, please click the link below to cancel the update request:</p>
    <a href="{{.Link}}">Cancel email update</a>
</body>
</html>
`

// DeleteAccountTemplate
var DeleteAccountTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Delete Account</title>
</head>
<body>
    <h2>Account Deletion Request</h2>
    <p>We received a request to delete your account. If you made this request, please confirm by clicking the link below:</p>
    <a href="{{.Link}}">Confirm account deletion</a>
</body>
</html>
`

var CancelDeleteAccountTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Delete Account</title>
</head>
<body>
    <h2>Account Deletion Request</h2>
    <p>We received a request to delete your account. If you made this request, please confirm by clicking the link below:</p>
    <a href="{{.Link}}">Confirm account deletion</a>
</body>
</html>
`
