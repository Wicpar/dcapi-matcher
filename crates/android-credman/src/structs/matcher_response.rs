use crate::*;

#[derive(Debug, Clone)]
pub enum MatcherResult<'a> {
    Single(CredentialEntry<'a>),
    Group(CredentialSet<'a>),
    InlineIssuance(InlineIssuanceEntry<'a>),
}

impl<'a> CredmanApply<()> for MatcherResult<'a> {
    fn apply(&self, _: ()) {
        match self {
            MatcherResult::Single(entry) => CredmanApply::apply(entry, ()),
            MatcherResult::Group(set) => CredmanApply::apply(set, ()),
            MatcherResult::InlineIssuance(entry) => CredmanApply::apply(entry, ()),
        }
    }
}

/// A collection of results to be returned by the Matcher.
///
/// This allows mixing multiple standalone entries and multiple sets.
#[derive(Debug, Clone, Default)]
pub struct MatcherResponse<'a> {
    pub results: Vec<MatcherResult<'a>>,
}

impl<'a> MatcherResponse<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_result(mut self, result: MatcherResult<'a>) -> Self {
        self.results.push(result);
        self
    }

    pub fn add_results<I>(mut self, results: I) -> Self
    where
        I: IntoIterator<Item = MatcherResult<'a>>,
    {
        self.results.extend(results);
        self
    }

    pub fn add_single(self, entry: CredentialEntry<'a>) -> Self {
        self.add_result(MatcherResult::Single(entry))
    }

    pub fn add_singles<I>(self, entries: I) -> Self
    where
        I: IntoIterator<Item = CredentialEntry<'a>>,
    {
        self.add_results(entries.into_iter().map(MatcherResult::Single))
    }

    pub fn add_group(self, set: CredentialSet<'a>) -> Self {
        self.add_result(MatcherResult::Group(set))
    }

    pub fn add_inline_issuance(self, entry: InlineIssuanceEntry<'a>) -> Self {
        self.add_result(MatcherResult::InlineIssuance(entry))
    }

    pub fn add_inline_issuances<I>(self, entries: I) -> Self
    where
        I: IntoIterator<Item = InlineIssuanceEntry<'a>>,
    {
        self.add_results(entries.into_iter().map(MatcherResult::InlineIssuance))
    }

    pub fn add_groups<I>(self, sets: I) -> Self
    where
        I: IntoIterator<Item = CredentialSet<'a>>,
    {
        self.add_results(sets.into_iter().map(MatcherResult::Group))
    }
}

impl<'a> CredmanApply<()> for MatcherResponse<'a> {
    fn apply(&self, _: ()) {
        for result in &self.results {
            CredmanApply::apply(result, ());
        }
    }
}
