Contributing to forwardproxy
=====================

Welcome! Thank you for choosing to be a part of our community. Caddy wouldn't be great without your involvement!

For starters, we invite you to join [the Caddy forum](https://caddy.community) where you can hang out with other Caddy users and developers.

### Contributing code

We hold contributions to a high standard for quality :bowtie:, so don't be surprised if we ask for revisions&mdash;even if it seems small or insignificant. Please don't take it personally. :wink: If your change is on the right track, we can guide you to make it mergable.

Here are some of the expectations we have of contributors:

- If your change is more than just a minor alteration, **open an issue to propose your change first.** This way we can avoid confusion, coordinate what everyone is working on, and ensure that changes are in-line with the project's goals and the best interests of its users. If there's already an issue about it, comment on the existing issue to claim it.

- **Keep pull requests small.** Smaller PRs are more likely to be merged because they are easier to review! We might ask you to break up large PRs into smaller ones. [An example of what we DON'T do.](https://twitter.com/iamdevloper/status/397664295875805184)

- **Keep related commits together in a PR.** We do want pull requests to be small, but you should also keep multiple related commits in the same PR if they rely on each other.

- **Write tests.** Tests are essential! Written properly, they ensure your change works, and that other changes in the future won't break your change. CI checks should pass.

- **Be extra careful.** Forwardproxy aims to help users in distress, and it is our duty to review changes extra meticulously.

- **Recommended reading**
	- [CodeReviewComments](https://github.com/golang/go/wiki/CodeReviewComments) for an idea of what we look for in good, clean Go code
	- [Linus Torvalds describes a good commit message](https://gist.github.com/matthewhudson/1475276)
	- [Best Practices for Maintainers](https://opensource.guide/best-practices/)
	- [Shrinking Code Review](https://alexgaynor.net/2015/dec/29/shrinking-code-review/)



- **[Squash](http://gitready.com/advanced/2009/02/10/squashing-commits-with-rebase.html) insignificant commits.** Every commit should be significant. Commits which merely rewrite a comment or fix a typo can be combined into another commit that has more substance. Interactive rebase can do this, or a simpler way is `git reset --soft <diverging-commit>` then `git commit -s`.

### Getting help using Caddy

If you have a question about using Caddy, [ask on our forum](https://caddy.community)! There will be more people there who can help you than just the Caddy developers who follow our issue tracker. Issues are not the place for usage questions.

Many people on the forums could benefit from your experience and expertise, too. Once you've been helped, consider giving back by answering other people's questions and participating in other discussions.


### Reporting bugs

Please follow the issue template so we have all the needed information. Unredacted&mdash;yes, actual values matter. We need to be able to repeat the bug using your instructions. Please simplify the issue as much as possible. The burden is on you to convince us that it is actually a bug in forwardproxy. This is easiest to do when you write clear, concise instructions so we can reproduce the behavior (even if it seems obvious). The more detailed and specific you are, the faster we will be able to help you!

We suggest reading [How to Report Bugs Effectively](http://www.chiark.greenend.org.uk/~sgtatham/bugs.html).

Please be kind. :smile: Remember that Caddy comes at no cost to you, and you're getting free support when we fix your issues. If we helped you, please consider helping someone else!


### Suggesting features

First, [search to see if your feature has already been requested](https://github.com/caddyserver/forwardproxy/issues). If it has, you can add a :+1: reaction to vote for it. If your feature idea is new, open an issue to request the feature. You don't have to follow the bug template for feature requests. Please describe your idea thoroughly so that we know how to implement it! Really vague requests may not be helpful or actionable and without clarification will have to be closed.

While we really do value your requests and implement many of them, not all features are a good fit for Caddy or forwardproxy. If a feature is not in the best interest of the Caddy project or its users in general, we may politely decline to implement it.

## Values

- A person is always more important than code. People don't like being handled "efficiently". But we can still process issues and pull requests efficiently while being kind, patient, and considerate.

- The ends justify the means, if the means are good. A good tree won't produce bad fruit. But if we cut corners or are hasty in our process, the end result will not be good.


## Responsible Disclosure

If you've found a security vulnerability, please email me, forwardproxy author, directly: Sergey dot Frolov at colorado.edu. I'll need enough information to verify the bug and make a patch. It will speed things up if you suggest a working patch. If your report is valid and a patch is released, we will not reveal your identity by default. If you wish to be credited, please give me the name to use. Thanks for responsibly helping forwardproxy users!


## Thank you

Thanks for your help! Caddy would not be what it is today without your contributions.
