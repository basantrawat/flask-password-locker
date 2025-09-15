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


    // --- START: Description Character Counter --- //
    const updateDescriptionCount = () => {
        const descriptionField = $('#description');
        if (descriptionField.length === 0) return;

        const maxLength = descriptionField.attr('maxlength');
        const currentLength = descriptionField.val().length;
        const remaining = maxLength - currentLength;
        const counter = $('#description-char-count');

        counter.text(remaining + ' characters remaining');
        counter.removeClass('text-gray-500 text-orange-500 text-red-600');

        if (remaining < 0) {
            counter.addClass('text-red-600');
            counter.text('Character limit exceeded by ' + Math.abs(remaining));
        } else if (remaining < 20) {
            counter.addClass('text-orange-500');
        } else {
            counter.addClass('text-gray-500');
        }
    };

    $(document).on('input', '#description', updateDescriptionCount);
    // Trigger on page load for edit page
    updateDescriptionCount();
    // --- END: Description Character Counter --- //


    // --- START: Event Delegation for Dynamic Content --- //
// Use event delegation for password toggling and copying to work on list/grid view
$(document).on('click', '.toggle-password', function(){
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

$(document).on('click', '.copy-password', function(){
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
        let originalIcon = icon.attr('class');
        icon.removeClass('fa-copy').addClass('fa-check text-green-500');
        setTimeout(function() {
            icon.attr('class', originalIcon).removeClass('text-green-500');
        }, 1500);
    });
});
// --- END: Event Delegation --- //
});
