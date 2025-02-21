from django import forms
from .models import Activity, Challenge, Lesson, Team, User, Notification, UserProfile
from django.contrib.auth.forms import SetPasswordForm as DjangoSetPasswordForm
from django.forms import DateTimeInput
from django.utils.html import strip_tags


class ChallengeForm(forms.ModelForm):
    section = forms.ChoiceField(choices=[], required=False, label="Section")  # Section dropdown dynamically populated

    class Meta:
        model = Challenge
        fields = [
            'name', 'category', 'content', 'file', 'link', 'hints',
            'points', 'visible', 'flag', 'deadline', 'scoring_type', 'section'  # Include section in fields
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'category': forms.Select(choices=Challenge.CATEGORY_CHOICES, attrs={'class': 'form-control'}),
            'content': forms.Textarea(attrs={'class': 'form-control', 'id': 'content-editor'}),
            'file': forms.FileInput(attrs={'class': 'form-control'}),
            'link': forms.URLInput(attrs={'class': 'form-control'}),
            'hints': forms.Textarea(attrs={'class': 'form-control'}),
            'points': forms.NumberInput(attrs={'class': 'form-control'}),
            'visible': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'flag': forms.TextInput(attrs={'class': 'form-control'}),
            'deadline': forms.DateTimeInput(attrs={'class': 'form-control', 'type': 'datetime-local'}),
            'scoring_type': forms.Select(attrs={'class': 'form-control'}),
            'section': forms.Select(attrs={'class': 'form-control'})  # Ensure section is rendered as a dropdown
        }


class LessonForm(forms.ModelForm):
    class Meta:
        model = Lesson
        fields = ['name', 'description', 'content', 'file', 'category', 'publish_date', 'visible']
        widgets = {
            'name': forms.Textarea(attrs={'class': 'form-control tinymce-editor', 'placeholder': 'Enter lesson name'}),  # Using TinyMCE
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3, 'placeholder': 'Enter lesson description'}),
            'content': forms.Textarea(attrs={'class': 'form-control tinymce-editor', 'placeholder': 'Enter lesson content'}),
            'file': forms.ClearableFileInput(attrs={'class': 'form-control'}),
            'category': forms.Select(attrs={'class': 'form-control'}),
            'publish_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'visible': forms.CheckboxInput(attrs={'class': 'form-check-input'})
        }

    def clean_name(self):
        """
        Ensure the name field is stored without HTML tags.
        """
        name = self.cleaned_data.get('name', '')
        return strip_tags(name)

    def save(self, commit=True):
        """
        Strip tags from the 'name' field before saving the instance.
        """
        instance = super().save(commit=False)
        instance.name = strip_tags(self.cleaned_data.get('name', ''))
        if commit:
            instance.save()
        return instance

class ActivityForm(forms.ModelForm):
    class Meta:
        model = Activity
        fields = ['category', 'activity_type', 'question', 'correct_answer', 'option_a', 'option_b', 'option_c', 'due_date']
        widgets = {
            'question': forms.Textarea(attrs={'rows': 4, 'class': 'form-control tinymce-editor'}),
            'category': forms.Select(attrs={'class': 'form-control'}),
            'activity_type': forms.Select(attrs={'class': 'form-control'}),
            'option_a': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Option A'}),
            'option_b': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Option B'}),
            'option_c': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Option C'}),
            'correct_answer': forms.TextInput(attrs={'class': 'form-control'}),
            'due_date': DateTimeInput(attrs={'type': 'datetime-local', 'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super(ActivityForm, self).__init__(*args, **kwargs)
        if self.instance and self.instance.activity_type == 'mcq':
            # Use a dropdown for correct_answer if the activity type is MCQ
            self.fields['correct_answer'].widget = forms.Select(
                choices=[
                    ('A', 'Option A'),
                    ('B', 'Option B'),
                    ('C', 'Option C'),
                ],
                attrs={'class': 'form-control'}
            )
        else:
            # Use a text input for identification questions
            self.fields['correct_answer'].widget = forms.TextInput(attrs={'class': 'form-control'})



class TeamForm(forms.ModelForm):
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control', 
            'placeholder': 'Enter a secure password'
        })
    )
    name = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-control', 
            'placeholder': 'Enter team name'
        })
    )

    class Meta:
        model = Team
        fields = ['name', 'password']

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super(TeamForm, self).__init__(*args, **kwargs)

    def save(self, commit=True):
        team = super().save(commit=False)
        team.set_password(self.cleaned_data['password'])
        if self.user:
            team.created_by = self.user
        if commit:
            team.save()
        return team

class InviteForm(forms.Form):
    invited_user = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter username to invite'
        })
    )

class NotificationForm(forms.Form):
    message = forms.CharField(max_length=255)

    def clean_message(self):
        message = self.cleaned_data['message']
        # Check if a notification with this message already exists
        if Notification.objects.filter(message=message).exists():
            raise forms.ValidationError("A notification with this message already exists.")
        return message
    
class NotificationForm(forms.Form):
    message = forms.CharField(max_length=255, widget=forms.TextInput(attrs={'placeholder': 'Enter notification message'}))
    recipients = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(is_staff=False),
        widget=forms.CheckboxSelectMultiple,
        required=True,
        label="Select Recipients"
    )

class EmailForm(forms.Form):
    email = forms.EmailField(label='Email', max_length=254)

class SetPasswordForm(DjangoSetPasswordForm):
    """
    A custom form for setting a new password.
    """
    # Add any custom fields or methods here if needed
    pass

class ProfilePictureForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['profile_picture']