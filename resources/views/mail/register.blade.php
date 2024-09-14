<!DOCTYPE html>
<html>
<head>
    <title>Custom Email</title>
</head>
<body>
    <h1>{{ $details['user']['name'] }}</h1>
    
    <a href="{{route('verify.user',$details['token'])}}">Register Verify</a>
</body>
</html>
