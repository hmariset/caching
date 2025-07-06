# Cursor Configuration

This directory contains Cursor-specific configuration for AI-assisted development.

## How Cursor @ Mentions Work

Cursor's @ system references files and rules directly. You only need these two simple commands:

### 🎯 Commit Message Generation
```
@commit-messages.mdc Generate a commit message for my staged changes
```

### 🌿 Branch Creation  
```
@branch-creation.mdc Create a branch for Jira issue KFLUXVNGD-358
```

## File Structure

```
.cursor/
├── README.md              # This file
└── rules/
    ├── commit-messages.mdc # Commit message formatting rules
    └── branch-creation.mdc # Branch creation from Jira issues
```

**That's it!** No extra directories or files cluttering your @ completions.

## Usage Tips

### @ Mentions Explained
- `@commit-messages.mdc` - References your commit formatting rules
- `@branch-creation.mdc` - References your branch creation rules
- These `.mdc` files contain all the logic and are automatically applied
- No other files are needed!

### Environment Setup
Your dev container is configured with:
- `GIT_AUTHOR_NAME` and `GIT_AUTHOR_EMAIL` environment variables
- These are automatically used in commit message footers

## Examples

### Generate a commit message:
```
@commit-messages.mdc Generate a commit message
```

### Create a new branch:
```
@branch-creation.mdc Create a branch for KFLUXVNGD-123
```

### Get help (without @):
```
What's the proper format for commit messages in this project?
```
(The AI will reference your rules automatically)

## Integration

These configurations work with:
- ✅ VS Code/Cursor editor settings (line length, rulers)
- ✅ Git environment variables (author info)  
- ✅ Conventional commits standard
- ✅ Jira issue integration
- ✅ issues.redhat.com lookup 