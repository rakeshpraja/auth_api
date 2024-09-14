<!DOCTYPE html>
<html>
<head>
    <title>Custom Email</title>
</head>
<body>
    <h1>Hi: {{ $details['user']['name'] }}</h1>
    
   <p>Enthe the otp:{{ $details['otp']}} for update user profile</p>
   <!-- <a href="{{route('update.profileverify',$details['token'])}}">click here</a> -->
</body>
</html>
