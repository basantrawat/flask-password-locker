$(document).ready(function() {

    // --- START: Password Strength Meter --- //

    $('#password').on('keyup input', function() {
        const password = $(this).val();
        const strengthBar = $('#password-strength-bar');
        const strengthFeedback = $('#password-strength-feedback');

        if (password.length === 0) {
            strengthBar.val(0);
            strengthFeedback.text('');
            return;
        }

        const result = zxcvbn(password);
        strengthBar.val(result.score);

        let feedbackText = result.feedback.warning || '';
        if (result.feedback.suggestions.length > 0) {
            feedbackText += ' ' + result.feedback.suggestions.join(' ');
        }
        strengthFeedback.text(feedbackText.trim());
    });

    // --- END: Password Strength Meter --- //


    // --- START: Advanced Password Generator --- //

    // Toggle visibility of password generator options
    $('#pass-generator-options-btn').click(function() {
        $('#pass-generator-options').slideToggle(200);
        $(this).find('i').toggleClass('fa-cog fa-times');
    });

    // Update length display on slider change
    $('#pass-length').on('input', function() {
        $('#pass-length-val').text($(this).val());
    });

    // Main password generation logic
    $('#generate-pass-btn').click(function() {
        const length = parseInt($('#pass-length').val());
        const includeUppercase = $('#pass-uppercase').is(':checked');
        const includeLowercase = $('#pass-lowercase').is(':checked');
        const includeNumbers = $('#pass-numbers').is(':checked');
        const includeSymbols = $('#pass-symbols').is(':checked');

        const upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const lowerChars = "abcdefghijklmnopqrstuvwxyz";
        const numberChars = "0123456789";
        const symbolChars = "!@#$%^&*()_+-=[]{};':\",./<>?";

        let charset = "";
        let password = [];

        if (includeUppercase) {
            charset += upperChars;
            password.push(upperChars.charAt(Math.floor(Math.random() * upperChars.length)));
        }
        if (includeLowercase) {
            charset += lowerChars;
            password.push(lowerChars.charAt(Math.floor(Math.random() * lowerChars.length)));
        }
        if (includeNumbers) {
            charset += numberChars;
            password.push(numberChars.charAt(Math.floor(Math.random() * numberChars.length)));
        }
        if (includeSymbols) {
            charset += symbolChars;
            password.push(symbolChars.charAt(Math.floor(Math.random() * symbolChars.length)));
        }

        if (charset === "") {
            alert("Please select at least one character type.");
            return;
        }

        const remainingLength = length - password.length;
        for (let i = 0; i < remainingLength; i++) {
            password.push(charset.charAt(Math.floor(Math.random() * charset.length)));
        }

        // Shuffle the array to ensure random character placement
        for (let i = password.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [password[i], password[j]] = [password[j], password[i]];
        }

        const finalPassword = password.join('');
        $('#password').val(finalPassword).trigger('keyup'); // Trigger keyup to update strength meter

        // Copy to clipboard and provide feedback
        navigator.clipboard.writeText(finalPassword).then(() => {
            const originalText = $(this).html();
            $(this).html('<i class="fas fa-check mr-2"></i>Copied!');
            setTimeout(() => {
                $(this).html(originalText);
            }, 2000);
        });
    });

    // --- END: Advanced Password Generator --- //


    // Password Visibility Toggle
    $('.toggle-password').click(function(){
        let input = $(this).prev('.password-field');
        let icon = $(this).find('i');
        if (input.attr('type') == 'password'){
            input.attr('type', 'text');
            icon.removeClass('fa-eye').addClass('fa-eye-slash');
        } else {
            input.attr('type', 'password');
            icon.removeClass('fa-eye-slash').addClass('fa-eye');
        }
    });

    // Copy to Clipboard for password list
    $('.copy-password').click(function(){
        let input = $(this).prev().prev('.password-field');
        let originalType = input.attr('type');
        if (originalType === 'password') {
            input.attr('type', 'text');
        }
        
        navigator.clipboard.writeText(input.val()).then(() => {
            if (originalType === 'password') {
                input.attr('type', 'password');
            }
            // Visual feedback
            let icon = $(this).find('i');
            icon.removeClass('fa-copy').addClass('fa-check');
            setTimeout(function() {
                icon.removeClass('fa-check').addClass('fa-copy');
            }, 1500);
        });
    });
});
